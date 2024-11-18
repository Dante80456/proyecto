const express = require('express');
const router = express.Router()
const controller = require('../controllers/authController')

//rutas para las vistas
router.get('/', controller.isAuthenticated, (req, res)=>{
    res.render('index', {user:req.user})
});
router.get('/login', (req, res)=>{
    res.render('login', {alert:false})
});
router.get('/register', (req, res)=>{
    res.render('register')
});

//rutas para los metodos del controller
router.post('/register', controller.registers)
router.post('/login', controller.login)
router.get('/logout', controller.logout)

module.exports = router