const http = require('http');

const authData = JSON.stringify({
  username: "admin",
  password: "admin_password" // Try "admin" / "admin" by default? Wait, I don't know the password...
});

const req = http.request({
  hostname: '127.0.0.1',
  port: 3232,
  path: '/api/users/login',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': authData.length
  }
}, (res) => {
  let body = '';
  res.on('data', d => body += d);
  res.on('end', () => {
    const token = JSON.parse(body).token;
    if (!token) { console.log('Login failed', body); return; }

    http.get({
      hostname: '127.0.0.1',
      port: 3232,
      path: '/api/users',
      headers: { 'Authorization': `Bearer ${token}` }
    }, (res2) => {
      let body2 = '';
      res2.on('data', d => body2 += d);
      res2.on('end', () => console.log('Users:', body2));
    });
  });
});

req.write(authData);
req.end();
