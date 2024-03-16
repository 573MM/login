const mysql = require('mysql');
const express = require('express');
const cors = require('cors');
const app = express();


app.use(cors());

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({extended : true}));
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const secretKey = process.env.SECRET_KEY;
const host = process.env.HOST;
const user = process.env.USER;
const passWord = process.env.PASSWORD;
const dataBase = process.env.DATABASE;



app.listen(3000, () => console.log("Start service on port 3000"));
app.use(express.json())
//middleware ใน Express ที่ใช้สำหรับการแปลงข้อมูล
app.use(express.urlencoded({ extended: true }))
//nosniff' ซึ่งมีไว้เพื่อป้องกันการทำงานของการทำอ่าน (sniffing) 
// Cross-Site Scripting (XSS) คืออะไร?
//Cross-Site Scripting (XSS) เป็นช่องโหว่ด้านความปลอดภัยบนเว็บแอปพลิเคชันที่อนุญาตให้ผู้โจมตีแทรกโค้ด JavaScript ที่เป็นอันตรายลงในหน้าเว็บที่ผู้ใช้รายอื่นดูไ
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
  });


const con = mysql.createConnection({
    host: host,
    user: user, 
    password: passWord, 
    database: dataBase,
  });
  
con.connect(function(err) {
    if (err) throw err;
    console.log("Connected!");
});

app.post("/register", async (req, res) => {
    const { username, password, sex = null, address = null, tel = null } = req.body;
    
    // const {username, password} = req.body;
    // const { sex = null, address = null, tel = null } = req.body; // กำหนดค่า default ให้กับฟิลด์อื่น ๆ
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    con.query("INSERT INTO customer (CustName, Password, Role, Sex, Address, Tel) VALUES (?, ?, 'user', ?, ?, ?);", [username, hashedPassword, sex, address, tel],(error,result,fields) => {
            if(error){
                return res.status(401).json({message : "Unable to complete registration"});
            }
            console.log("hashedPassword"+hashedPassword);
            return res.status(201).header('Location', 'login.html').json({ message: "Register successfully" });
        }
    )

})


app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  con.query("SELECT CustName, Password FROM customer WHERE CustName = ?", [username], async function (err, result, fields) {
      if (err) {
          return res.status(401).json({ message: "Can't connect to database" });
      }
      // ตรวจสอบว่ามีผู้ใช้งานที่ตรงกับชื่อผู้ใช้ที่ใส่เข้ามาหรือไม่
      if (!result[0]) {
        return res.status(400).json({ message: "Username or Password incorrect" });
    }
      // เช็ครหัสผ่านว่าตรงกับที่เก็บในฐานข้อมูลหรือไม่
      const passwordMatch = await bcrypt.compare(password, result[0].Password);
      //const passwordMatch = password === result[0].Password;
      console.log("result"+result[0].Password);
      if (!passwordMatch) {
          return res.status(401).json({ message: "Username or Password incorrect2",test:result[0].Password ,pp:passwordMatch});
      } else {
          const token = jwt.sign({ username: username }, secretKey, {
              expiresIn: '1h',
          });
          return res.status(200).json({ token,message:"Login successfully" });
      }
  });
});
/*app.post("/login", async (req, res) => {



      con.query("SELECT CustName, Password FROM customer WHERE CustName = ?", [username], async function(err, result, fields) {
          con.end(); // Close the connection
          if (err) {
              console.error('Error executing query:', err);
              return res.status(401).json({ message: "Can't connect to database" });
          }
          
          if (!result[0]) {
              return res.status(400).json({ message: "Username or Password incorrect1" });
          }
          const salt = await bcrypt.genSalt(10);
          //const hashedPassword = await bcrypt.hash(password, salt);
          const passwordMatch = await bcrypt.compare(password, result[0].Password);
          console.log(password + " " + result[0].Password);
          if (!passwordMatch) {
              return res.status(401).json({ message: "Username or Password incorrect2" });
          } else {
              const token = jwt.sign({ username: username }, secretKey, {
                  expiresIn: '1h',
              });
              return res.status(200).json({ token });
          }
      });
  });
*/



  app.get('/protected', (req, res) => {
    const token = req.headers.authorization.split(' ')[1]
  
    try {
      const decoded = jwt.verify(token, secretKey)
  
      res.json({
        message: 'Hello! You are authorized',
        decoded,
      })
    } catch (error) {
      res.status(401).json({
        message: 'Unauthorized',
        error: error.message,
      })
    }
})







