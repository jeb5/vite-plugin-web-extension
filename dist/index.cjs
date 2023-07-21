'use strict';

var node_crypto = require('node:crypto');
var fsExtra = require('fs-extra');
var promises = require('node:fs/promises');
var path = require('node:path');
var vite = require('vite');
var parse = require('content-security-policy-parser');
var getEtag = require('etag');
var MagicString = require('magic-string');

const addHmrSupportToCsp = (hmrServerOrigin, inlineScriptHashes, contentSecurityPolicyStr) => {
    const inlineScriptHashesArr = Array.from(inlineScriptHashes);
    const scriptSrcs = ["'self'", hmrServerOrigin].concat(inlineScriptHashesArr || []);
    const contentSecurityPolicy = parse(contentSecurityPolicyStr || "");
    contentSecurityPolicy["script-src"] = scriptSrcs.concat(contentSecurityPolicy["script-src"]);
    contentSecurityPolicy["object-src"] = ["'self'"].concat(contentSecurityPolicy["object-src"]);
    return Object.keys(contentSecurityPolicy)
        .map((key) => {
        return (`${key} ` +
            contentSecurityPolicy[key]
                .filter((c, idx) => contentSecurityPolicy[key].indexOf(c) === idx) // Dedupe
                .join(" "));
    })
        .join("; ");
};

function getNormalizedFileName(fileName, includeExt = true) {
    let { dir, name, ext } = path.parse(vite.normalizePath(path.normalize(fileName)));
    if (!dir) {
        return `${name}${includeExt ? ext : ""}`;
    }
    dir = dir.startsWith("/") ? dir.slice(1) : dir;
    return `${dir}/${name}${includeExt ? ext : ""}`;
}
function getInputFileName(inputFileName, root) {
    return `${root}/${getNormalizedFileName(inputFileName, true)}`;
}
function getOutputFileName(inputFileName) {
    return getNormalizedFileName(inputFileName, false);
}

function getAdditionalInputAsWebAccessibleResource(input) {
    if (!input.webAccessible) {
        return null;
    }
    return {
        matches: input.webAccessible.matches,
        extension_ids: input.webAccessible.extensionIds,
        use_dynamic_url: true,
    };
}

function getNormalizedAdditionalInput(input) {
    const webAccessibleDefaults = {
        matches: ["<all_urls>"],
        excludeEntryFile: false,
    };
    if (typeof input === "string") {
        return {
            fileName: input,
            webAccessible: webAccessibleDefaults,
        };
    }
    if (typeof input.webAccessible === "boolean") {
        return {
            ...input,
            webAccessible: input.webAccessible ? webAccessibleDefaults : null,
        };
    }
    return {
        ...input,
        webAccessible: {
            excludeEntryFile: webAccessibleDefaults.excludeEntryFile,
            ...input.webAccessible,
        },
    };
}

function getScriptHtmlLoaderFile(name, scriptSrcs) {
    const scriptsHtml = scriptSrcs
        .map((scriptSrc) => {
        return `<script type="module" src="${scriptSrc}"></script>`;
    })
        .join("");
    return {
        fileName: `${name}.html`,
        source: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />${scriptsHtml}</head></html>`,
    };
}
function getScriptLoaderFile(scriptFileName, inputFileNames) {
    const outputFile = getOutputFileName(scriptFileName);
    const importStatements = inputFileNames
        .filter((fileName) => Boolean(fileName))
        .map((fileName) => {
        return fileName.startsWith("http")
            ? `"${fileName}"`
            : `chrome.runtime.getURL("${fileName}")`;
    })
        .map((importPath) => `await import(${importPath})`)
        .join(";");
    return {
        fileName: `${outputFile}.js`,
        source: `(async()=>{${importStatements}})();`,
    };
}
function getServiceWorkerLoaderFile(inputFileNames) {
    const importStatements = inputFileNames
        .filter((fileName) => Boolean(fileName))
        .map((fileName) => {
        return fileName.startsWith("http") ? fileName : `/${fileName}`;
    })
        .map((importPath) => `import "${importPath}";`)
        .join("\n");
    return {
        fileName: `serviceWorker.js`,
        source: importStatements,
    };
}
function getScriptLoaderForOutputChunk(contentScriptFileName, chunk) {
    if (!chunk.imports.length && !chunk.dynamicImports.length) {
        return null;
    }
    return getScriptLoaderFile(contentScriptFileName, [chunk.fileName]);
}

const virtualModules = new Map();
function setVirtualModule(id, source) {
    virtualModules.set(id, source);
}
function getVirtualModule(id) {
    return virtualModules.get(id) ?? null;
}

class DevBuilder {
    constructor(viteConfig, pluginOptions, viteDevServer, manifest) {
        this.viteConfig = viteConfig;
        this.pluginOptions = pluginOptions;
        this.viteDevServer = viteDevServer;
        this.manifest = manifest;
        this.hmrServerOrigin = "";
        this.inlineScriptHashes = new Set();
        this.hmrViteClientUrl = "";
        this.outDir = path.resolve(process.cwd(), this.viteConfig.root, this.viteConfig.build.outDir);
    }
    async writeBuild({ devServerPort, manifestHtmlFiles, }) {
        this.hmrServerOrigin = this.getHmrServerOrigin(devServerPort);
        this.hmrViteClientUrl = `${this.hmrServerOrigin}/@vite/client`;
        await fsExtra.emptyDir(this.outDir);
        const publicDir = path.resolve(process.cwd(), this.viteConfig.root, this.viteConfig.publicDir);
        await fsExtra.copy(publicDir, this.outDir);
        await this.writeManifestHtmlFiles(manifestHtmlFiles);
        await this.writeManifestContentScriptFiles();
        await this.writeManifestContentCssFiles();
        await this.writeManifestAdditionalInputFiles();
        await this.writeBuildFiles(manifestHtmlFiles);
        this.updateContentSecurityPolicyForHmr();
        await promises.writeFile(`${this.outDir}/manifest.json`, JSON.stringify(this.manifest, null, 2));
    }
    async writeBuildFiles(_manifestHtmlFiles) { }
    getContentSecurityPolicyWithHmrSupport(contentSecurityPolicy) {
        return addHmrSupportToCsp(this.hmrServerOrigin, this.inlineScriptHashes, contentSecurityPolicy);
    }
    async writeManifestHtmlFiles(htmlFileNames) {
        for (const fileName of htmlFileNames) {
            const absoluteFileName = getInputFileName(fileName, this.viteConfig.root);
            await this.writeManifestHtmlFile(fileName, absoluteFileName);
            this.viteDevServer.watcher.on("change", async (path) => {
                if (vite.normalizePath(path) !== absoluteFileName) {
                    return;
                }
                await this.writeManifestHtmlFile(fileName, absoluteFileName);
            });
        }
    }
    async writeManifestHtmlFile(fileName, absoluteFileName) {
        let content = getVirtualModule(absoluteFileName) ??
            (await promises.readFile(absoluteFileName, {
                encoding: "utf-8",
            }));
        content = await this.viteDevServer.transformIndexHtml(fileName, content);
        const devServerFileName = `${this.hmrServerOrigin}${path
            .resolve(this.viteConfig.root, fileName)
            .slice(this.viteConfig.root.length)}`;
        const baseElement = `<base href="${devServerFileName}">`;
        const headRE = /<head.*?>/ims;
        if (content.match(headRE)) {
            content = content.replace(headRE, `$&${baseElement}`);
        }
        else {
            content = content.replace(/<html.*?>/ims, `$&<head>${baseElement}</head>`);
        }
        this.parseInlineScriptHashes(content);
        const outFile = `${this.outDir}/${fileName}`;
        const outFileDir = path.dirname(outFile);
        await fsExtra.ensureDir(outFileDir);
        await promises.writeFile(outFile, content);
        return fileName;
    }
    parseInlineScriptHashes(_content) { }
    async writeManifestContentScriptFiles() {
        if (!this.manifest.content_scripts) {
            return;
        }
        for (const [contentScriptIndex, script,] of this.manifest.content_scripts.entries()) {
            if (!script.js) {
                continue;
            }
            for (const [scriptJsIndex, fileName] of script.js.entries()) {
                const loaderFileName = await this.writeManifestScriptFile(fileName);
                this.manifest.content_scripts[contentScriptIndex].js[scriptJsIndex] =
                    loaderFileName;
            }
        }
    }
    async writeManifestScriptFile(fileName) {
        const outputFileName = getOutputFileName(fileName);
        const scriptLoaderFile = getScriptLoaderFile(outputFileName, [
            this.hmrViteClientUrl,
            `${this.hmrServerOrigin}/${fileName}`,
        ]);
        const outFile = `${this.outDir}/${scriptLoaderFile.fileName}`;
        const outFileDir = path.dirname(outFile);
        await fsExtra.ensureDir(outFileDir);
        await promises.writeFile(outFile, scriptLoaderFile.source);
        return scriptLoaderFile.fileName;
    }
    async writeManifestContentCssFiles() {
        if (!this.manifest.content_scripts) {
            return;
        }
        for (const [contentScriptIndex, script,] of this.manifest.content_scripts.entries()) {
            if (!script.css) {
                continue;
            }
            for (const [cssIndex, fileName] of script.css.entries()) {
                const absoluteFileName = getInputFileName(fileName, this.viteConfig.root);
                const outputFileName = `${getOutputFileName(fileName)}.css`;
                this.manifest.content_scripts[contentScriptIndex].css[cssIndex] =
                    outputFileName;
                await this.writeManifestAssetFile(outputFileName, absoluteFileName);
                this.viteDevServer.watcher.on("change", async (path) => {
                    if (vite.normalizePath(path) !== absoluteFileName) {
                        return;
                    }
                    await this.writeManifestAssetFile(outputFileName, fileName);
                });
            }
        }
    }
    async writeManifestAssetFile(outputFileName, fileName) {
        const { default: source } = (await this.viteDevServer.ssrLoadModule(fileName));
        const loaderFile = {
            fileName: outputFileName,
            source,
        };
        const outFile = `${this.outDir}/${loaderFile.fileName}`;
        const outFileDir = path.dirname(outFile);
        await fsExtra.ensureDir(outFileDir);
        await promises.writeFile(outFile, loaderFile.source);
        return loaderFile.fileName;
    }
    async writeManifestAdditionalInputFile(type, input) {
        const additionalInput = getNormalizedAdditionalInput(input);
        const { fileName, webAccessible } = additionalInput;
        const absoluteFileName = getInputFileName(fileName, this.viteConfig.root);
        let outputFileName = "";
        switch (type) {
            case "html":
                outputFileName = await this.writeManifestHtmlFile(fileName, absoluteFileName);
                break;
            case "scripts":
                outputFileName = await this.writeManifestScriptFile(fileName);
                break;
            case "styles":
                const cssFileName = `${getOutputFileName(fileName)}.css`;
                outputFileName = await this.writeManifestAssetFile(cssFileName, absoluteFileName);
                break;
            default:
                throw new Error(`Invalid additionalInput type of ${type}`);
        }
        if (webAccessible && !webAccessible.excludeEntryFile) {
            const webAccessibleResource = getAdditionalInputAsWebAccessibleResource(additionalInput);
            if (webAccessibleResource) {
                this.addWebAccessibleResource({
                    fileName: outputFileName,
                    webAccessibleResource,
                });
            }
        }
    }
    getHmrServerOrigin(devServerPort) {
        if (typeof this.viteConfig.server.hmr === "boolean") {
            throw new Error("Vite HMR is misconfigured");
        }
        return `http://${this.viteConfig.server.hmr.host}:${devServerPort}`;
    }
}

class DevBuilderManifestV2 extends DevBuilder {
    updateContentSecurityPolicyForHmr() {
        this.manifest.content_security_policy =
            this.getContentSecurityPolicyWithHmrSupport(this.manifest.content_security_policy);
    }
    parseInlineScriptHashes(content) {
        const matches = content.matchAll(/<script.*?>([^<]+)<\/script>/gs);
        for (const match of matches) {
            const shasum = node_crypto.createHash("sha256");
            shasum.update(match[1]);
            this.inlineScriptHashes.add(`'sha256-${shasum.digest("base64")}'`);
        }
    }
    async writeManifestAdditionalInputFiles() {
        if (!this.pluginOptions.additionalInputs) {
            return;
        }
        for (const [type, inputs] of Object.entries(this.pluginOptions.additionalInputs)) {
            if (!inputs) {
                return;
            }
            for (const input of inputs) {
                if (!input) {
                    continue;
                }
                await this.writeManifestAdditionalInputFile(type, input);
            }
        }
    }
    addWebAccessibleResource({ fileName, }) {
        this.manifest.web_accessible_resources ??= [];
        this.manifest.web_accessible_resources.push(fileName);
    }
}

function addInputScriptsToOptionsInput(inputScripts, optionsInput) {
    const optionsInputObject = getOptionsInputAsObject(optionsInput);
    inputScripts.forEach(([output, input]) => {
        input = input.trim();
        if (optionsInputObject[output] &&
            optionsInputObject[output].trim() !== input) {
            throw new Error(`Inputs (${optionsInputObject[output]}) and (${input}) share an output identifier of (${output}). Rename one of the inputs to prevent output resolution issues.`);
        }
        optionsInputObject[output] = input;
    });
    return optionsInputObject;
}
function getOptionsInputAsObject(input) {
    if (typeof input === "string") {
        if (!input.trim()) {
            return {};
        }
        return {
            [input]: input,
        };
    }
    else if (input instanceof Array) {
        if (!input.length) {
            return {};
        }
        const inputObject = {};
        input.forEach((input) => (inputObject[input] = input));
        return inputObject;
    }
    return input ?? {};
}
function getChunkInfoFromBundle(bundle, chunkId) {
    const normalizedId = getNormalizedFileName(chunkId);
    return Object.values(bundle).find((chunk) => {
        if (chunk.type === "asset") {
            return false;
        }
        return (chunk.facadeModuleId?.endsWith(normalizedId) ||
            chunk.fileName.endsWith(normalizedId));
    });
}
function findMatchingOutputAsset(bundle, normalizedInputId) {
    return Object.values(bundle).find((chunk) => {
        if (chunk.type === "chunk") {
            return;
        }
        if (chunk.name) {
            return normalizedInputId.endsWith(chunk.name);
        }
        return chunk.fileName.endsWith(normalizedInputId);
    });
}
function getOutputInfoFromBundle(type, bundle, inputId) {
    switch (type) {
        case "styles":
            return getCssAssetInfoFromBundle(bundle, inputId);
        case "scripts":
            return getChunkInfoFromBundle(bundle, inputId);
        case "html":
            return findMatchingOutputAsset(bundle, inputId);
        default:
            throw new Error(`Invalid additionalInput type of ${type}`);
    }
}
function getCssAssetInfoFromBundle(bundle, assetFileName) {
    const normalizedInputId = getNormalizedFileName(assetFileName, false);
    return findMatchingOutputAsset(bundle, `${normalizedInputId}.css`);
}

class ManifestParser {
    constructor(pluginOptions, viteConfig) {
        this.pluginOptions = pluginOptions;
        this.viteConfig = viteConfig;
        this.parsedMetaDataChunkIds = new Set();
        this.inputManifest = JSON.parse(JSON.stringify(this.pluginOptions.manifest));
    }
    async parseInput() {
        const parseResult = {
            manifest: this.inputManifest,
            inputScripts: [],
            emitFiles: [],
        };
        return this.pipe(parseResult, this.parseInputHtmlFiles, this.parseInputContentScripts, this.parseInputBackgroundScripts, this.parseInputAdditionalInputs, ...this.getParseInputMethods());
    }
    async writeDevBuild(devServerPort) {
        await this.createDevBuilder().writeBuild({
            devServerPort,
            manifestHtmlFiles: this.getHtmlFileNames(this.inputManifest),
        });
    }
    async parseOutput(bundle) {
        let result = {
            inputScripts: [],
            emitFiles: [],
            manifest: this.inputManifest,
        };
        result = await this.parseOutputAdditionalInputs(result, bundle);
        result = await this.parseOutputContentScripts(result, bundle);
        for (const parseMethod of this.getParseOutputMethods()) {
            result = await parseMethod(result, bundle);
        }
        if (this.pluginOptions.optimizeWebAccessibleResources !== false) {
            result = this.optimizeWebAccessibleResources(result);
        }
        result.emitFiles.push({
            type: "asset",
            fileName: "manifest.json",
            source: JSON.stringify(result.manifest, null, 2),
        });
        return result;
    }
    setDevServer(server) {
        this.viteDevServer = server;
    }
    parseInputAdditionalInputs(result) {
        if (!this.pluginOptions.additionalInputs) {
            return result;
        }
        Object.values(this.pluginOptions.additionalInputs).forEach((additionalInputArray) => {
            additionalInputArray.forEach((additionalInput) => {
                const fileName = typeof additionalInput === "string"
                    ? additionalInput
                    : additionalInput.fileName;
                if (fileName.includes("*")) {
                    throw new Error(`additionalInput "${fileName}" is invalid. Must be a single file.`);
                }
                this.addInputToParseResult(fileName, result);
            });
        });
        return result;
    }
    parseInputHtmlFiles(result) {
        this.getHtmlFileNames(result.manifest).forEach((htmlFileName) => this.addInputToParseResult(htmlFileName, result));
        return result;
    }
    parseInputContentScripts(result) {
        result.manifest.content_scripts?.forEach((script) => {
            script.js?.forEach((fileName) => this.addInputToParseResult(fileName, result));
            script.css?.forEach((fileName) => this.addInputToParseResult(fileName, result));
        });
        return result;
    }
    parseOutputContentCss(cssFileName, bundle) {
        const cssAssetInfo = getCssAssetInfoFromBundle(bundle, cssFileName);
        if (!cssAssetInfo) {
            throw new Error(`Failed to find CSS asset info for ${cssFileName}`);
        }
        return {
            cssFileName: cssAssetInfo.fileName,
        };
    }
    parseOutputContentScript(scriptFileName, result, bundle) {
        const chunkInfo = getChunkInfoFromBundle(bundle, scriptFileName);
        if (!chunkInfo) {
            throw new Error(`Failed to find chunk info for ${scriptFileName}`);
        }
        return this.parseOutputChunk(scriptFileName, chunkInfo, result, bundle);
    }
    parseOutputAdditionalInput(type, additionalInput, result, bundle) {
        const { fileName, webAccessible } = additionalInput;
        const chunkInfo = getOutputInfoFromBundle(type, bundle, fileName);
        if (!chunkInfo) {
            throw new Error(`Failed to find chunk info for ${fileName}`);
        }
        const parseResult = chunkInfo.type === "asset"
            ? this.parseOutputAsset(type, fileName, chunkInfo, result, bundle)
            : this.parseOutputChunk(fileName, chunkInfo, result, bundle);
        if (webAccessible === null) {
            parseResult.webAccessibleFiles.clear();
        }
        else if (!webAccessible.excludeEntryFile) {
            parseResult.webAccessibleFiles.add(parseResult.fileName);
        }
        return parseResult;
    }
    parseOutputAsset(type, inputFileName, outputAsset, result, bundle) {
        delete bundle[outputAsset.fileName];
        const fileName = `${getOutputFileName(inputFileName)}.${this.getAdditionalInputTypeFileExtension(type)}`;
        result.emitFiles.push({
            type: "asset",
            fileName,
            source: outputAsset.source,
        });
        return {
            fileName,
            webAccessibleFiles: new Set(),
        };
    }
    parseOutputChunk(inputFileName, outputChunk, result, bundle) {
        const scriptLoaderFile = getScriptLoaderForOutputChunk(inputFileName, outputChunk);
        const metadata = this.getMetadataforChunk(outputChunk.fileName, bundle, Boolean(scriptLoaderFile));
        outputChunk.code = outputChunk.code.replace(new RegExp("import.meta.PLUGIN_WEB_EXT_CHUNK_CSS_PATHS", "g"), `[${[...metadata.css].map((path) => `"${path}"`).join(",")}]`);
        const fileName = scriptLoaderFile?.fileName ?? `${outputChunk.name}.js`;
        if (scriptLoaderFile) {
            result.emitFiles.push({
                type: "asset",
                fileName,
                source: scriptLoaderFile.source,
            });
        }
        else {
            delete bundle[outputChunk.fileName];
            result.emitFiles.push({
                type: "asset",
                fileName,
                source: outputChunk.code,
            });
        }
        return {
            fileName,
            webAccessibleFiles: new Set([
                ...metadata.assets,
                ...metadata.css,
            ]),
        };
    }
    getAdditionalInputTypeFileExtension(type) {
        switch (type) {
            case "html":
                return "html";
            case "scripts":
                return "js";
            case "styles":
                return "css";
            default:
                throw new Error(`Unknown additionalInput type of ${type}`);
        }
    }
    addInputToParseResult(fileName, result) {
        const inputFile = getInputFileName(fileName, this.viteConfig.root);
        const outputFile = getOutputFileName(fileName);
        result.inputScripts.push([outputFile, inputFile]);
        return result;
    }
    pipe(initialValue, ...fns) {
        return fns.reduce((previousValue, fn) => fn.call(this, previousValue), initialValue);
    }
    getMetadataforChunk(chunkId, bundle, includeChunkAsAsset = false, metadata = null) {
        if (metadata === null) {
            this.parsedMetaDataChunkIds.clear();
            metadata = {
                css: new Set(),
                assets: new Set(),
            };
        }
        if (this.parsedMetaDataChunkIds.has(chunkId)) {
            return metadata;
        }
        const chunkInfo = getChunkInfoFromBundle(bundle, chunkId);
        if (!chunkInfo) {
            return metadata;
        }
        if (includeChunkAsAsset) {
            metadata.assets.add(chunkInfo.fileName);
        }
        chunkInfo.viteMetadata.importedCss.forEach(metadata.css.add, metadata.css);
        chunkInfo.viteMetadata.importedAssets.forEach(metadata.assets.add, metadata.assets);
        this.parsedMetaDataChunkIds.add(chunkId);
        chunkInfo.imports.forEach((chunkId) => (metadata = this.getMetadataforChunk(chunkId, bundle, true, metadata)));
        chunkInfo.dynamicImports.forEach((chunkId) => (metadata = this.getMetadataforChunk(chunkId, bundle, true, metadata)));
        return metadata;
    }
    parseInputBackgroundScripts(result) {
        // @ts-expect-error - Force support of event pages in manifest V3 (Firefox)
        if (!result.manifest.background?.scripts) {
            return result;
        }
        const htmlLoaderFile = getScriptHtmlLoaderFile("background", 
        // @ts-expect-error - Force support of event pages in manifest V3 (Firefox)
        result.manifest.background.scripts.map((script) => {
            if (/^[\.\/]/.test(script)) {
                return script;
            }
            return `/${script}`;
        }));
        const inputFile = getInputFileName(htmlLoaderFile.fileName, this.viteConfig.root);
        const outputFile = getOutputFileName(htmlLoaderFile.fileName);
        result.inputScripts.push([outputFile, inputFile]);
        setVirtualModule(inputFile, htmlLoaderFile.source);
        // @ts-expect-error - Force support of event pages in manifest V3 (Firefox)
        delete result.manifest.background.scripts;
        // @ts-expect-error - Force support of event pages in manifest V3 (Firefox)
        result.manifest.background.page = htmlLoaderFile.fileName;
        return result;
    }
}

class ManifestV2 extends ManifestParser {
    createDevBuilder() {
        return new DevBuilderManifestV2(this.viteConfig, this.pluginOptions, this.viteDevServer, this.inputManifest);
    }
    getHtmlFileNames(manifest) {
        return [
            manifest.background?.page,
            manifest.browser_action?.default_popup,
            manifest.options_ui?.page,
            manifest.devtools_page,
            manifest.chrome_url_overrides?.newtab,
            manifest.chrome_url_overrides?.history,
            manifest.chrome_url_overrides?.bookmarks,
            manifest.sidebar_action?.default_panel,
        ]
            .filter((fileName) => typeof fileName === "string")
            .map((fileName) => fileName.split(/[\?\#]/)[0]);
    }
    getParseInputMethods() {
        return [];
    }
    getParseOutputMethods() {
        return [];
    }
    async parseOutputContentScripts(result, bundle) {
        const webAccessibleResources = new Set(result.manifest.web_accessible_resources ?? []);
        result.manifest.content_scripts?.forEach((script) => {
            script.js?.forEach((scriptFileName, index) => {
                const parsedContentScript = this.parseOutputContentScript(scriptFileName, result, bundle);
                script.js[index] = parsedContentScript.fileName;
                parsedContentScript.webAccessibleFiles.forEach(webAccessibleResources.add, webAccessibleResources);
            });
            script.css?.forEach((cssFileName, index) => {
                const parsedContentCss = this.parseOutputContentCss(cssFileName, bundle);
                script.css[index] = parsedContentCss.cssFileName;
            });
        });
        if (webAccessibleResources.size > 0) {
            result.manifest.web_accessible_resources = Array.from(webAccessibleResources);
        }
        return result;
    }
    async parseOutputAdditionalInputs(result, bundle) {
        if (!this.pluginOptions.additionalInputs) {
            return result;
        }
        for (const [type, inputs] of Object.entries(this.pluginOptions.additionalInputs)) {
            for (const input of inputs) {
                const additionalInput = getNormalizedAdditionalInput(input);
                const parsedFile = this.parseOutputAdditionalInput(type, additionalInput, result, bundle);
                if (parsedFile.webAccessibleFiles.size) {
                    result.manifest.web_accessible_resources = [
                        ...(result.manifest.web_accessible_resources ?? []),
                        ...parsedFile.webAccessibleFiles,
                    ];
                }
            }
        }
        return result;
    }
    optimizeWebAccessibleResources(result) {
        if (!result.manifest.web_accessible_resources) {
            return result;
        }
        result.manifest.web_accessible_resources =
            result.manifest.web_accessible_resources.sort();
        return result;
    }
}

class DevBuilderManifestV3 extends DevBuilder {
    async writeBuildFiles() {
        await this.writeManifestServiceWorkerFiles(this.manifest);
    }
    updateContentSecurityPolicyForHmr() {
        this.manifest.content_security_policy ??= {};
        this.manifest.content_security_policy.extension_pages =
            this.getContentSecurityPolicyWithHmrSupport(this.manifest.content_security_policy.extension_pages);
    }
    async writeManifestServiceWorkerFiles(manifest) {
        if (!manifest.background?.service_worker) {
            return;
        }
        const fileName = manifest.background?.service_worker;
        const serviceWorkerLoader = getServiceWorkerLoaderFile([
            this.hmrViteClientUrl,
            `${this.hmrServerOrigin}/${fileName}`,
        ]);
        manifest.background.service_worker = serviceWorkerLoader.fileName;
        const outFile = `${this.outDir}/${serviceWorkerLoader.fileName}`;
        const outFileDir = path.dirname(outFile);
        await fsExtra.ensureDir(outFileDir);
        await promises.writeFile(outFile, serviceWorkerLoader.source);
    }
    async writeManifestAdditionalInputFiles() {
        if (!this.pluginOptions.additionalInputs) {
            return;
        }
        for (const [type, inputs] of Object.entries(this.pluginOptions.additionalInputs)) {
            if (!inputs) {
                return;
            }
            for (const input of inputs) {
                if (!input) {
                    continue;
                }
                await this.writeManifestAdditionalInputFile(type, input);
            }
        }
    }
    addWebAccessibleResource({ fileName, webAccessibleResource, }) {
        this.manifest.web_accessible_resources ??= [];
        if (this.pluginOptions.useDynamicUrlWebAccessibleResources === false) {
            delete webAccessibleResource["use_dynamic_url"];
        }
        // @ts-expect-error - allow additional web_accessible_resources properties
        this.manifest.web_accessible_resources.push({
            resources: [fileName],
            ...webAccessibleResource,
        });
    }
}

class ManifestV3 extends ManifestParser {
    createDevBuilder() {
        return new DevBuilderManifestV3(this.viteConfig, this.pluginOptions, this.viteDevServer, this.inputManifest);
    }
    getHtmlFileNames(manifest) {
        return [
            manifest.action?.default_popup,
            manifest.options_ui?.page,
            manifest.devtools_page,
            manifest.chrome_url_overrides?.newtab,
            manifest.chrome_url_overrides?.history,
            manifest.chrome_url_overrides?.bookmarks,
            manifest.side_panel?.default_path,
            manifest.sidebar_action?.default_panel,
        ]
            .filter((fileName) => typeof fileName === "string")
            .map((fileName) => fileName.split(/[\?\#]/)[0]);
    }
    getParseInputMethods() {
        return [this.parseInputBackgroundServiceWorker];
    }
    getParseOutputMethods() {
        return [this.parseOutputServiceWorker];
    }
    parseInputBackgroundServiceWorker(result) {
        if (!result.manifest.background?.service_worker) {
            return result;
        }
        const serviceWorkerScript = result.manifest.background?.service_worker;
        this.addInputToParseResult(serviceWorkerScript, result);
        result.manifest.background.type = "module";
        return result;
    }
    async parseOutputContentScripts(result, bundle) {
        const webAccessibleResources = new Set([...(result.manifest.web_accessible_resources ?? [])]);
        result.manifest.content_scripts?.forEach((script) => {
            script.js?.forEach((scriptFileName, index) => {
                const parsedContentScript = this.parseOutputContentScript(scriptFileName, result, bundle);
                script.js[index] = parsedContentScript.fileName;
                if (parsedContentScript.webAccessibleFiles.size) {
                    const resource = {
                        resources: Array.from(parsedContentScript.webAccessibleFiles),
                        matches: script.matches.map((matchPattern) => {
                            const pathMatch = /[^:\/]\//.exec(matchPattern);
                            if (!pathMatch) {
                                return matchPattern;
                            }
                            const path = matchPattern.slice(pathMatch.index + 1);
                            if (["/", "/*"].includes(path)) {
                                return matchPattern;
                            }
                            return matchPattern.replace(path, "/*");
                        }),
                    };
                    if (this.pluginOptions.useDynamicUrlWebAccessibleResources !== false) {
                        // @ts-ignore - use_dynamic_url is supported, but not typed
                        resource.use_dynamic_url = true;
                    }
                    webAccessibleResources.add(resource);
                }
            });
            script.css?.forEach((cssFileName, index) => {
                const parsedContentCss = this.parseOutputContentCss(cssFileName, bundle);
                script.css[index] = parsedContentCss.cssFileName;
            });
        });
        if (webAccessibleResources.size > 0) {
            result.manifest.web_accessible_resources = Array.from(webAccessibleResources);
        }
        return result;
    }
    async parseOutputAdditionalInputs(result, bundle) {
        if (!this.pluginOptions.additionalInputs) {
            return result;
        }
        for (const [type, inputs] of Object.entries(this.pluginOptions.additionalInputs)) {
            for (const input of inputs) {
                const additionalInput = getNormalizedAdditionalInput(input);
                const parsedFile = this.parseOutputAdditionalInput(type, additionalInput, result, bundle);
                if (parsedFile.webAccessibleFiles.size) {
                    const webAccessibleResource = getAdditionalInputAsWebAccessibleResource(additionalInput);
                    if (!webAccessibleResource) {
                        continue;
                    }
                    if (this.pluginOptions.useDynamicUrlWebAccessibleResources === false) {
                        delete webAccessibleResource["use_dynamic_url"];
                    }
                    result.manifest.web_accessible_resources ??= [];
                    // @ts-expect-error - allow additional web_accessible_resources properties
                    result.manifest.web_accessible_resources.push({
                        resources: [...parsedFile.webAccessibleFiles],
                        ...webAccessibleResource,
                    });
                }
            }
        }
        return result;
    }
    async parseOutputServiceWorker(result, bundle) {
        const serviceWorkerFileName = result.manifest.background?.service_worker;
        if (!serviceWorkerFileName) {
            return result;
        }
        const chunkInfo = getChunkInfoFromBundle(bundle, serviceWorkerFileName);
        if (!chunkInfo) {
            throw new Error(`Failed to find chunk info for ${serviceWorkerFileName}`);
        }
        const serviceWorkerLoader = getServiceWorkerLoaderFile([
            chunkInfo.fileName,
        ]);
        result.manifest.background.service_worker = serviceWorkerLoader.fileName;
        result.emitFiles.push({
            type: "asset",
            fileName: serviceWorkerLoader.fileName,
            source: serviceWorkerLoader.source,
        });
        return result;
    }
    optimizeWebAccessibleResources(result) {
        if (!result.manifest.web_accessible_resources) {
            return result;
        }
        const resourceMap = new Map();
        result.manifest.web_accessible_resources.forEach((resource) => {
            const resourceKey = JSON.stringify({
                ...resource,
                resources: [],
            });
            if (resourceMap.has(resourceKey)) {
                const existingEntry = resourceMap.get(resourceKey);
                resourceMap.set(resourceKey, {
                    ...existingEntry,
                    ...resource,
                    resources: [
                        ...new Set([...existingEntry.resources, ...resource.resources]),
                    ].sort(),
                });
            }
            else {
                resourceMap.set(resourceKey, resource);
            }
        });
        result.manifest.web_accessible_resources = [...resourceMap.values()];
        return result;
    }
}

class ManifestParserFactory {
    static getParser(pluginOptions, viteConfig) {
        switch (pluginOptions.manifest.manifest_version) {
            case 2:
                return new ManifestV2(pluginOptions, viteConfig);
            case 3:
                return new ManifestV3(pluginOptions, viteConfig);
            default:
                throw new Error(`No parser available for manifest_version ${
                // @ts-expect-error - Allow showing manifest version for invalid usage
                manifest.manifest_version ?? 0}`);
        }
    }
}

// Modifies the vite HMR client to support various web extension features including:
//  Exporting a function to add HMR style injection targets
//  Tweaks to support running in a service worker context
const viteClientModifier = (req, res, next) => {
    const _originalEnd = res.end;
    // @ts-ignore
    res.end = function end(chunk, ...otherArgs) {
        if (req.url === "/@vite/client" && typeof chunk === "string") {
            chunk = addCustomStyleFunctionality(chunk);
            chunk = addServiceWorkerSupport(chunk);
            res.setHeader("Etag", getEtag(chunk, { weak: true }));
        }
        // @ts-ignore
        return _originalEnd.call(this, chunk, ...otherArgs);
    };
    next();
};
function addCustomStyleFunctionality(source) {
    if (!/const sheetsMap/.test(source) ||
        !/document\.head\.appendChild\(style\)/.test(source) ||
        !/document\.head\.removeChild\(style\)/.test(source) ||
        (!/style\.textContent = content/.test(source) &&
            !/style\.innerHTML = content/.test(source))) {
        console.error("Web extension HMR style support disabled -- failed to update vite client");
        return source;
    }
    source = source.replace("const sheetsMap", "const styleTargets = new Set(); const styleTargetsStyleMap = new Map(); const sheetsMap");
    source = source.replace("export {", "export { addStyleTarget, ");
    source = source.replace("document.head.appendChild(style)", "styleTargets.size ? styleTargets.forEach(target => addStyleToTarget(style, target)) : document.head.appendChild(style)");
    source = source.replace("document.head.removeChild(style)", "styleTargetsStyleMap.get(style) ? styleTargetsStyleMap.get(style).forEach(style => style.parentNode.removeChild(style)) : document.head.removeChild(style)");
    const styleProperty = /style\.textContent = content/.test(source)
        ? "style.textContent"
        : "style.innerHTML";
    const lastStyleInnerHtml = source.lastIndexOf(`${styleProperty} = content`);
    source =
        source.slice(0, lastStyleInnerHtml) +
            source
                .slice(lastStyleInnerHtml)
                .replace(`${styleProperty} = content`, `${styleProperty} = content; styleTargetsStyleMap.get(style)?.forEach(style => ${styleProperty} = content)`);
    source += `
    function addStyleTarget(newStyleTarget) {            
      for (const [, style] of sheetsMap.entries()) {
        addStyleToTarget(style, newStyleTarget, styleTargets.size !== 0);
      }

      styleTargets.add(newStyleTarget);
    }

    function addStyleToTarget(style, target, cloneStyle = true) {
      const addedStyle = cloneStyle ? style.cloneNode(true) : style;
      target.appendChild(addedStyle);

      styleTargetsStyleMap.set(style, [...(styleTargetsStyleMap.get(style) ?? []), addedStyle]);
    }
  `;
    return source;
}
function guardDocumentUsageWithDefault(source, documentUsage, defaultValue) {
    return source.replace(documentUsage, `('document' in globalThis ? ${documentUsage} : ${defaultValue})`);
}
function addServiceWorkerSupport(source) {
    // update location.reload usages
    source = source.replaceAll(/(window\.)?location.reload\(\)/g, "(location.reload?.() ?? (typeof chrome !== 'undefined' ? chrome.runtime?.reload?.() : ''))");
    // add document guards
    source = guardDocumentUsageWithDefault(source, "document.querySelectorAll(overlayId).length", "false");
    source = guardDocumentUsageWithDefault(source, "document.visibilityState", `"visible"`);
    source = guardDocumentUsageWithDefault(source, `document.querySelectorAll('link')`, "[]");
    source = source.replace("const enableOverlay =", `const enableOverlay = ('document' in globalThis) &&`);
    return source;
}

// Update vite user config with settings necessary for the plugin to work
function updateConfigForExtensionSupport(config, manifest) {
    config.build ??= {};
    if (!config.build.target) {
        switch (manifest.manifest_version) {
            case 2:
                config.build.target = ["chrome64", "firefox89"]; // minimum browsers with import.meta.url and content script dynamic import
                break;
            case 3:
                config.build.target = ["chrome91"];
                break;
        }
    }
    config.build.modulePreload ??= false;
    config.build.rollupOptions ??= {};
    config.build.rollupOptions.input ??= {};
    config.optimizeDeps ??= {};
    config.optimizeDeps.exclude = [
        ...(config.optimizeDeps.exclude ?? []),
        "/@vite/client",
    ];
    config.server ??= {};
    if (config.server.hmr === true || !config.server.hmr) {
        config.server.hmr = {};
    }
    config.server.hmr.protocol = "ws"; // required for content script hmr to work on https
    config.server.hmr.host = "localhost";
    return config;
}
// Vite asset helper rewrites usages of import.meta.url to self.location for broader
//   browser support, but content scripts need to reference assets via import.meta.url
// This transform rewrites self.location back to import.meta.url
function transformSelfLocationAssets(code, resolvedViteConfig) {
    if (code.includes("new URL") && code.includes(`self.location`)) {
        let updatedCode = null;
        const selfLocationUrlPattern = /\bnew\s+URL\s*\(\s*('[^']+'|"[^"]+"|`[^`]+`)\s*,\s*self\.location\s*\)/g;
        let match;
        while ((match = selfLocationUrlPattern.exec(code))) {
            const { 0: exp, index } = match;
            if (!updatedCode)
                updatedCode = new MagicString(code);
            updatedCode.overwrite(index, index + exp.length, exp.replace("self.location", "import.meta.url"));
        }
        if (updatedCode) {
            return {
                code: updatedCode.toString(),
                map: resolvedViteConfig.build.sourcemap
                    ? updatedCode.generateMap({ hires: true })
                    : null,
            };
        }
    }
    return null;
}

function webExtension(pluginOptions) {
    if (!pluginOptions.manifest) {
        throw new Error("Missing manifest definition");
    }
    let viteConfig;
    let emitQueue = [];
    let manifestParser;
    return {
        name: "webExtension",
        enforce: "post",
        config(config) {
            return updateConfigForExtensionSupport(config, pluginOptions.manifest);
        },
        configResolved(resolvedConfig) {
            viteConfig = resolvedConfig;
        },
        configureServer(server) {
            server.middlewares.use(viteClientModifier);
            server.httpServer.once("listening", () => {
                manifestParser.setDevServer(server);
                manifestParser.writeDevBuild(server.config.server.port);
            });
        },
        async options(options) {
            manifestParser = ManifestParserFactory.getParser(pluginOptions, viteConfig);
            const { inputScripts, emitFiles } = await manifestParser.parseInput();
            options.input = addInputScriptsToOptionsInput(inputScripts, options.input);
            emitQueue = emitQueue.concat(emitFiles);
            return options;
        },
        buildStart() {
            emitQueue.forEach((file) => {
                this.emitFile(file);
                this.addWatchFile(file.fileName ?? file.name);
            });
            emitQueue = [];
        },
        resolveId(id) {
            return getVirtualModule(id) ? id : null;
        },
        load(id) {
            return getVirtualModule(id);
        },
        transform(code) {
            return transformSelfLocationAssets(code, viteConfig);
        },
        async generateBundle(_options, bundle) {
            const { emitFiles } = await manifestParser.parseOutput(bundle);
            emitFiles.forEach(this.emitFile);
        },
    };
}

module.exports = webExtension;
