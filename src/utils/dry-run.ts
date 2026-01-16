import { IntelService } from '../services/intelService';
import logger from './logger';

async function test() {
    const target = '105.119.38.234';
    logger.info(`Starting dry-run analysis for ${target}...`);
    try {
        const result = await IntelService.analyze(target);
        console.log(JSON.stringify(result, null, 2));
        process.exit(0);
    } catch (err) {
        logger.error('Analysis failed', err);
        process.exit(1);
    }
}

test();
