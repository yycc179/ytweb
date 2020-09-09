const app = require('express')()
    , https = require('https')
    , bodyParser = require('body-parser')
    , fs = require('fs')
    , net = require('net')
    , config = require('./config/')
    , { sha1, hmac } = require('utility')
    , { exec } = require('child_process')

app.set('x-powered-by', false)

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

function onListening() {
    console.log('Server Listening on ', this.address())
}

https.createServer({
    key: fs.readFileSync(config.PATH.priv, 'utf8'),
    cert: fs.readFileSync(config.PATH.cert, 'utf8')
}, app)
    .listen(process.env.PORT || '443')
    .on('listening', onListening);


if (app.get('env') === 'development') {
    require('http').createServer(app)
        .listen(80)
        .on('listening', onListening);
}

app.get('/', (req, res) => {
    const { s, js, h } = req.query

    var a = 'ver'

    if (s && js) {
        if (sha1(s + js + process.env['HASH_SALT_YTS']) != h) {
            //return res.status(403).send('verify err!\n')
        }
        a = s + ' ' + js
    }

    const client = net.createConnection({ port: 3001, timeout: 150000 }, () => {
        client.write(a)
    })

    client.on('data', data => {
        res.send(data.toString());
        client.end();
    }).on('timeout', () => {
        res.send('Connect service timeout!\n');
        client.end();
    }).on('error', e => {
        res.send('Connect service error!\n');
        client.end();
    })
});

app.get('/api/keylist', (req, res) => {
    fs.readdir(config.PATH.api_key, (err, files) => {
        if (files && files.length) {
            id = Math.floor(Math.random() * files.length);
            res.setHeader('Content-Type', 'text/plain')
            res.sendFile(`${config.PATH.api_key}${id}.key`)
        }
        else {
            res.send('keylist err!');
        }
    });
})


function verify_signature(req, res, next) {
    const { p } = req.query;
    const salt = (p == 'web' ? process.env['HOOK_SECRET_WEB'] : process.env['HOOK_SECRET_YTS']) || 'none'

    req.up_param = p;

    const x_s = req.headers['x-hub-signature']
    const s = 'sha1=' + hmac('sha1', salt, JSON.stringify(req.body), 'hex')

    if (s == x_s) {
        return next()
    }
    res.json({ err: 1, p, x_s, salt })
}

function do_update(req, res, next) {
    exec(`update ${req.up_param} ${req.body.after}`, (error, stdout) => {
        if (error) {
            res.send(error)
            return child.kill()
        }
        res.send(stdout)
    })
}

app.post('/githook/', verify_signature, do_update);
