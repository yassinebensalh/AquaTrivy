"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {   
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const os = __importStar(require("os"));
const util = __importStar(require("util"));
const tool = __importStar(require("azure-pipelines-tool-lib"));
const task = require("azure-pipelines-task-lib");
const latestTrivyVersion = "v0.50.1";
const tmpPath = "/tmp/";
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        var _a, _b, _c;
        console.log("Preparing output location...");


        //#########################################""

        let imageNames = task.getInput("imageName", false);
        if (typeof imageNames === 'undefined') {
            throw new Error("You must at Least Commit/Update one Microservice in the project");
        }
        console.log("docker image's Names" + imageNames);
        let DockerImagesNamesArray = imageNames.split(" ");
        console.log(DockerImagesNamesArray);
        let outputPaths = [];
        for (let i = 0; i < DockerImagesNamesArray.length; i++) {
            const outputPath = tmpPath + "trivy-results-" + DockerImagesNamesArray[i] + "-" + Math.random() + ".json";
            task.rmRF(outputPath);
            outputPaths.push(outputPath);
        }

        //#########################################""

        let scanPath = task.getInput("path", false);
        let image = task.getInput("image", false);
        let ignoreUnfixed = task.getBoolInput("ignoreUnfixed", false);
        let severities = (_a = task.getInput("severities", false)) !== null && _a !== void 0 ? _a : "";
        let options = (_b = task.getInput("options", false)) !== null && _b !== void 0 ? _b : "";
        let scanners = (_c = task.getInput("scanners", false)) !== null && _c !== void 0 ? _c : "vuln,misconfig,secret";
        if (scanPath === undefined && image === undefined) {
            throw new Error("You must specify something to scan. Use either the 'image' or 'path' option.");
        }
        if (scanPath !== undefined && image !== undefined) {
            throw new Error("You must specify only one of the 'image' or 'path' options. Use multiple task definitions if you want to scan multiple targets.");
        }
        
        let runners = [];
        for (let i = 0; i < DockerImagesNamesArray.length; i++) {
            runners[i] = yield createRunner(task.getBoolInput("docker", false));
            if (task.getBoolInput("debug", false)) {
                runners[i].arg("--debug");
            }
        }
        let resultTest = 0;
        if (image !== undefined) {
            for (let i = 0; i < DockerImagesNamesArray.length; i++) {
                let fullImageName = image + DockerImagesNamesArray[i] + ":0.0.1";
                configureScan(runners[i], "image", fullImageName, outputPaths[i], severities, ignoreUnfixed, options, scanners);

                console.log("Running Trivy...");
                let result = runners[i].execSync();
                if (result.code != 0) {
                    resultTest++;
                }
                
                console.log("Publishing JSON results... for "+ outputPaths[i]);
                task.addAttachment("JSON_RESULT", "trivy" + Math.random() + ".json", outputPaths[i]);
                console.log("Done! for " + outputPaths[i]);
            }
        }

        if (resultTest === 0) {
            task.setResult(task.TaskResult.Succeeded, "No problems found.");
        }
        else {
            task.setResult(task.TaskResult.Failed, "Failed: Trivy detected problems.");
        }
        
        
    });
}

function createRunner(docker) {
    return __awaiter(this, void 0, void 0, function* () {
        const version = task.getInput('version', true);
        if (version === undefined) {
            throw new Error("version is not defined");
        }
        if (!docker) {
            console.log("Run requested using local Trivy binary...");
            const trivyPath = yield "trivy";
            return task.tool(trivyPath);
        }
    });
}
function configureScan(runner, type, target, outputPath, severities, ignoreUnfixed, options, scanners) {
    console.log("Configuring options for image scan...");
    let exitCode = task.getInput("exitCode", false);
    if (exitCode === undefined) {
        exitCode = "1";
    }
    runner.arg([type]);
    runner.arg(["--exit-code", exitCode]);
    runner.arg(["--format", "json"]);
    runner.arg(["--output", outputPath]);
    // runner.arg(["--scanners", scanners]);
    if (severities.length) {
        runner.arg(["--severity", severities]);
    }
    if (ignoreUnfixed) {
        runner.arg(["--ignore-unfixed"]);
    }
    if (options.length) {
        runner.line(options);
    }
    runner.arg(target);
}



run().catch((err) => {
    task.setResult(task.TaskResult.Failed, err.message);
});
