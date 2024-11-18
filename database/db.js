const { error } = require('console');
const mysql = require('mysql');
const router = require('../routes/router');


const conexion = mysql.createConnection({
    host : process.env.DB_HOST,
    user : process.env.DB_USER,
    password : process.env.DB_PASS,
    database : process.env.DB_DATABASE,
})


conexion.connect((error)=> {
    if(error){
        console.log('El error de conexion es: '+error)
        return
    }
    console.log('La conexion fue exitosa')
})

module.exports = conexion