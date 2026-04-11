const path = require('path');
const fs = require('fs');
const docsPath = path.join(__dirname, 'docs', '.vitepress', 'dist');
console.log('Docs Path:', docsPath);
console.log('Exists:', fs.existsSync(docsPath));
if (fs.existsSync(docsPath)) {
    console.log('Contents:', fs.readdirSync(docsPath));
}
const landingPath = path.join(__dirname, 'landing-page');
console.log('Landing Path:', landingPath);
console.log('Exists:', fs.existsSync(landingPath));
