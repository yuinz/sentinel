const url = 'https://sentinel.risksignal.name.ng/v2/evaluate';
const token = 'sl_e2f9224af4a5a371c6a58098bfa54e38e5e6fd3b00c31a90';

fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: '105.119.17.103', path: '/scan' })
}).then(async r => {
    console.log(r.status);
    console.log(await r.text());
});
