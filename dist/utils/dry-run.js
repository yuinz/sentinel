"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const intelService_1 = require("../services/intelService");
const logger_1 = __importDefault(require("./logger"));
async function test() {
    const target = '105.119.38.234';
    logger_1.default.info(`Starting dry-run analysis for ${target}...`);
    try {
        const result = await intelService_1.IntelService.analyze(target);
        console.log(JSON.stringify(result, null, 2));
        process.exit(0);
    }
    catch (err) {
        logger_1.default.error('Analysis failed', err);
        process.exit(1);
    }
}
test();
