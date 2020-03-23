//import dependensi yang digunakan
const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const session = require('express-session');

//membuat aplikasi dengan framework express
const app = express();

//membuat aplikasi menggunakan session
app.use (session ({
    secret : 'secret',
    resave : true,
    saveUninitialized : true
}));

//inisialisasi port yang digunakan
const port = 7000;

//inisialisasi secret key yang digunakan oleh JWT
const secretKey = 'thisisverysecretKey';

//membuat aplikasi menggunakan bodyParser
app.use (bodyParser.json());
app.use (bodyParser.urlencoded ({
    extended : true 
}));

//inisialisasi koneksi ke database
const db = mysql.createConnection ({
    host : '127.0.0.1',
    port : '3306',
    user : 'root',
    password : '',
    database : 'jual_masker'
});

const isAuthorized = (request, result, next) => {

    //cek apakah user sudah mengirim header 'x-api-key'
    if (typeof(request.headers['x-api-key']) == 'undefined') {
        return result.status(403).json ({
            success : false,
            message : 'Unauthorized. Token is not provided'
        })
    }

    //mendapatkan token dari header
    let token = request.headers['x-api-key']

    //melakukan verifikasi token yang dikirim user
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return result.status(403).json ({
                success : false,
                message : 'Unauthorized. Token is invalid'
            })
        }
    })

    //lanjut ke next request
    next()
}

// mencocokkan username dan password yang ada di database
app.post('/login/penjual', function(request, response) {
    let data = request.body
    let username = data.username;
    let password = data.password;
    if (username && password) {
        db.query ('select * from penjual where username = ? and password = ?', [username, password], function(error, results, fields) {
            if (results.length > 0) {
                request.session.loggedin = true;
                request.session.username = data.username;
                response.redirect('/login/penjual');
            } else {
                response.send('Username dan/ Password salah!');
            }
            response.end();
        });
    } else {
        response.send('Enter Username and Password!');
        response.end();
    }
});

app.get('/login/penjual', function(request, results) {
    if(request.session.loggedin) {
        let data = request.body
        let token = jwt.sign(data.username + '|' + data.password, secretKey)
        results.json ({
            success : true, 
            message : 'Login success, welcome back!',
            token : token 
        })
    } else {
        results.json ({
            success : false,
            message : 'Mohon login terlebih dahulu!'
        })
    }
    results.end();
});

