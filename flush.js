const url = 'https://sentinel.risksignal.name.ng/v1/cache/flush';
const token = 'sl_e2f9224af4a5a371c6a58098bfa54e38e5e6fd3b00c31a90';

fetch(url, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` }
}).then(async r => {
    console.log(r.status);
    console.log(await r.text());
});
