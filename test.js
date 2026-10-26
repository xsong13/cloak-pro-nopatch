import { launch } from './dist/index.js';

const LICENSE_KEY = 'dev_local';

const baseOpts = {
    headless: false,
    licenseKey: LICENSE_KEY,

};


const browser = await launch({ ...baseOpts });

const page = await browser.newPage();
await page.goto('https://baidu.com');
console.log('第一个实例:', await page.title());


const b2 = await launch({ ...baseOpts });

const page2 = await b2.newPage();
await page2.goto('https://example.com');
console.log('第二个实例:', await page2.title());

// 想开几个开几个
const b3 = await launch({ ...baseOpts });
const p3 = await b3.newPage();
await p3.goto('https://example.com');
console.log('第三个实例:', await p3.title());
