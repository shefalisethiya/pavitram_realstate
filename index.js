const express = require("express");
const path = require("path");
const mysql = require("mysql2");
const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  next();
});
const cors = require("cors");
const fs = require("fs");
const session = require("express-session");
const nodemailer = require("nodemailer");
app.use(
  session({
    secret: "your_secret_key",
    saveUninitialized: true,
    cookie: { secure: false },
  })
);
app.use(cors({ origin: "http://localhost:8085", credentials: true }));
const uploadDir = path.join(__dirname, "public", "upload");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log("✅ Upload directory created:", uploadDir);
}
app.use(express.urlencoded({ extended: true }));
const ejs = require("ejs");
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
const port = 8085;
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.render("/index");
});
const connection = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "realstate",
});
app.post("/register", async (req, res) => {
  try {
    const { fullname, email, mobileNo, whatsappNo, password, userType } =
      req.body;
    if (
      !fullname ||
      !email ||
      !mobileNo ||
      !whatsappNo ||
      !password ||
      !userType
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }
    let status;
    let redirectUrl;
    switch (userType.toLowerCase()) {
      case "agent":
        status = 0;
        break;
      case "agency":
        status = 2;
        break;
      case "job seeker":
        status = 3;
        break;
      case "recruiter":
        status = 4;
        redirectUrl = `/recruitermoreinfo?fullname=${encodeURIComponent(
          fullname
        )}&email=${encodeURIComponent(email)}&mobileNo=${encodeURIComponent(
          mobileNo
        )}&password=${encodeURIComponent(password)}`;
        break;
      default:
        return res.status(400).json({ message: "Invalid userType" });
    }
    if (!redirectUrl) {
      redirectUrl = `/hiring?fullname=${encodeURIComponent(
        fullname
      )}&email=${encodeURIComponent(email)}&mobileNo=${encodeURIComponent(
        mobileNo
      )}&password=${encodeURIComponent(password)}`;
    }
    connection.query(
      "SELECT * FROM register WHERE email = ? OR mobileNo = ?",
      [email, mobileNo],
      async (err, results) => {
        if (err)
          return res
            .status(500)
            .json({ message: "Database error", error: err });

        if (results.length > 0) {
          return res.status(400).json({ message: "User already exists" });
        }
        connection.query(
          "INSERT INTO register (fullName, email, mobileNo, whattsappNo, password, status) VALUES (?, ?, ?, ?, ?, ?)",
          [fullname, email, mobileNo, whatsappNo, password, status],
          (err, result) => {
            if (err)
              return res
                .status(500)
                .json({ message: "Error registering user", error: err });
            res.status(200).json({
              message: "User registered successfully",
              redirect: redirectUrl,
            });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});
app.post("/adminregister", async (req, res) => {
  try {
    const { fullname, email, mobileNo, whatsappNo, password, userType } =
      req.body;
    if (
      !fullname ||
      !email ||
      !mobileNo ||
      !whatsappNo ||
      !password ||
      !userType
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }
    let status;
    if (userType.toLowerCase() === "admin") {
      status = 1;
    } else {
      return res.status(400).json({ message: "Invalid userType" });
    }
    connection.query(
      "SELECT * FROM register WHERE email = ? OR mobileNo = ?",
      [email, mobileNo],
      async (err, results) => {
        if (err)
          return res
            .status(500)
            .json({ message: "Database error", error: err });

        if (results.length > 0) {
          return res.status(400).json({ message: "User already exists" });
        }
        connection.query(
          "INSERT INTO register (fullName, email, mobileNo, whattsappNo, password, status,approval) VALUES (?, ?, ?, ?, ?, ?,1)",
          [fullname, email, mobileNo, whatsappNo, password, status],
          (err, result) => {
            if (err)
              return res
                .status(500)
                .json({ message: "Error registering user", error: err });

            res.status(200).json({
              message: "admin registered successfully",
              redirect: "/adminlogin",
            });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});
app.post("/adminlogin", (req, res) => {
  console.log(req.body);
  const { mobileNo, password, userType } = req.body;
  if (!userType) {
    return res.status(400).json({ message: "User type is required!" });
  }
  const query = "SELECT * FROM register WHERE mobileNo = ? AND password = ?";
  connection.query(query, [mobileNo, password], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }

    if (results.length === 0) {
      return res
        .status(400)
        .json({ message: "Invalid mobile number or password" });
    }
    const user = results[0];
    let redirectUrl = "";
    let message = "";
    switch (userType.toLowerCase()) {
      case "admin":
        if (user.status === 1) {
          message = "Admin login successful";
          redirectUrl = "/admindashboard";
        }
        break;
      case "agent":
        if (user.status === 0) {
          message = "Agent login successful";
          redirectUrl = "/agentdashboard";
        }
        break;
      case "agency":
        if (user.status === 2) {
          message = "Agency login successful";
          redirectUrl = "/agencydashboard";
        }
        break;
      case "jobseeker":
        if (user.status === 3) {
          message = "Jobseeker login successful";
          redirectUrl = "/nakuridashboard";
        }
        break;
      case "recruiter":
        if (user.status === 4) {
          message = "recuriter login successful";
          redirectUrl = "/recuriterdashboard";
        }
        break;
      default:
        return res
          .status(403)
          .json({ message: "Unauthorized access or incorrect status" });
    }

    if (!redirectUrl) {
      return res
        .status(403)
        .json({ message: "Unauthorized access or incorrect status" });
    }
    req.session.user = user;
    return res.json({
      message,
      user,
      redirect: redirectUrl,
    });
  });
});
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Error logging out" });
    }
    res.render("logout");
  });
});

app.get("/hiring", (req, res) => {
  console.log("Query Parameters:", req.query);
  const { fullname, email, mobileNo, password } = req.query;
  res.render("hiring", { fullName: fullname, email, mobileNo, password });
});
app.get("/recruitermoreinfo", (req, res) => {
  console.log("Query Parameters:", req.query);
  const { fullname, email, mobileNo, password } = req.query;
  res.render("recruitermoreinfo", {
    fullName: fullname,
    email,
    mobileNo,
    password,
  });
});
app.get("/myprofile", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.status(401).json({ message: "Unauthorized access" });
  }
  const userFullName = req.session.user.fullName;
  const getUserQuery = "SELECT * FROM register WHERE fullName = ?";
  connection.query(getUserQuery, [userFullName], (err, userResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    if (userResults.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.render("myprofile", {
      allData: userResults,
      user: req.session.user,
    });
  });
});
app.get("/buildingmaterials", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.status(401).json({ message: "Unauthorized access" });
  }
  const fullName = req.session.user;
  return res.render("buildingmaterials", {
    fullName: fullName,
  });
});
app.put("/updateUser", async (req, res) => {
  const { fullName, email, mobileNo, whatsappNo, password } = req.body;
  try {
    const updatedUser = await User.findOneAndUpdate(
      { email },
      { fullName, mobileNo, whatsappNo, password },
      { new: true }
    );
    if (!updatedUser)
      return res.status(404).json({ message: "User not found" });

    res.json({ message: "User updated successfully", user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});
app.post("/inquiry", (req, res) => {
  const { email, mobileNo } = req.body;
  if (!email || !mobileNo) {
    return res
      .status(400)
      .json({ message: "Email and Mobile No are required!" });
  }
  console.log("Received Data:", req.body);
  const query = "INSERT INTO inquiry (email, phone) VALUES (?, ?)";
  connection.query(query, [email, mobileNo], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res
        .status(500)
        .json({ message: "Database error", error: err.message });
    }
    res.status(201).json({
      message: "OTP will be successfully send on ur mail pls check ur email!",
      redirect: "/otpverify",
    });
  });
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});
app.get("/adminlogin", (req, res) => {
  return res.render("adminlogin");
});
app.get("/index", (req, res) => {
  return res.render("index");
});

app.get("/meet-schedule", (req, res) => {
  return res.render("meet_schedule");
});
app.get("/meetdata", (req, res) => {
  const fullName = req.session.user.fullName;
  const query = "SELECT * FROM meet_schedule";
  connection.query(query, (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).send("Database error");
    }
    res.render("meetdata", { meetData: results, fullName });
  });
});
app.get("/otpverify", (req, res) => {
  return res.render("otpverify");
});
app.get("/approval", (req, res) => {
  const getAllQuery = "SELECT * FROM register";

  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    const agentCount = allResults.filter((user) => user.status === 0).length;
    const adminCount = allResults.filter((user) => user.status === 1).length;
    const agencyCount = allResults.filter((user) => user.status === 2).length;
    const verifiedCount = allResults.filter(
      (user) => Number(user.approval) === 1
    ).length;
    const notVerifiedCount = allResults.filter(
      (user) => Number(user.approval) === 0
    ).length;
    return res.render("approval", {
      allData: allResults,
      agentCount,
      adminCount,
      agencyCount,
      verifiedCount,
      notVerifiedCount,
    });
  });
});
app.get("/agentdata", (req, res) => {
  const getAllQuery = "SELECT * FROM register where status=0 AND approval=1 ";
  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    return res.render("agentdata", {
      allData: allResults,
    });
  });
});
app.get("/agencydata", (req, res) => {
  const getAllQuery = "SELECT * FROM register where status=2 AND approval=0 ";
  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    return res.render("agencydata", {
      allData: allResults,
    });
  });
});
app.get("/agetallpostedProperty", (req, res) => {
  const getAllQuery = "SELECT * FROM meet_schedule WHERE current_status = 0";

  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    console.log("Fetched Data:", allResults);
    return res.render("updatePropertyCurrentStatus", {
      allData: allResults,
    });
  });
});
app.get("/getpostedProperty", (req, res) => {
  const getAllQuery = "SELECT * FROM property WHERE approve = 0";

  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    console.log("Fetched Data:", allResults);
    return res.render("updatePropertyapprovalStatus", {
      allData: allResults,
    });
  });
});
app.get("/adminsignup", (req, res) => {
  return res.render("adminsignup");
});
app.get("/adminpostproper", (req, res) => {
  const getAllQuery = "SELECT * FROM register";
  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    const agentCount = allResults.filter((user) => user.status === 0).length;
    const adminCount = allResults.filter((user) => user.status === 1).length;
    const agencyCount = allResults.filter((user) => user.status === 2).length;
    const verifiedCount = allResults.filter(
      (user) => Number(user.approval) === 1
    ).length;
    const notVerifiedCount = allResults.filter(
      (user) => Number(user.approval) === 0
    ).length;
    return res.render("adminpostproper", {
      allData: allResults,
      agentCount: agentCount,
      adminCount: adminCount,
      agencyCount: agencyCount,
      verifiedCount: verifiedCount,
      notVerifiedCount: notVerifiedCount,
    });
  });
});
app.get("/adminpostproper", (req, res) => {
  const getAllQuery = "SELECT * FROM register";

  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    const agentCount = allResults.filter((user) => user.status === 0).length;
    const adminCount = allResults.filter((user) => user.status === 1).length;
    const agencyCount = allResults.filter((user) => user.status === 2).length;
    const verifiedCount = allResults.filter(
      (user) => Number(user.approval) === 1
    ).length;
    const notVerifiedCount = allResults.filter(
      (user) => Number(user.approval) === 0
    ).length;
    return res.render("adminpostproper", {
      allData: allResults,
      agentCount: agentCount,
      adminCount: adminCount,
      agencyCount: agencyCount,
      verifiedCount: verifiedCount,
      notVerifiedCount: notVerifiedCount,
    });
  });
});
const multer = require("multer");
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "public", "uploads"));
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });
app.post("/registerProperty", upload.single("uploadImage"), (req, res) => {
  const {
    PropertyName,
    OwnerName,
    PropertyType,
    PropertyStatus,
    totalfloor,
    floorNo,
    transactionsType,
    Face,
    TypeOfOwner,
    YearOfConstruction,
    price,
    BookingAmount,
    address,
    city,
    landMark,
    flooring,
    overLooking,
    additionalRoom,
    description,
    propertyAction,
  } = req.body;
  const propertyImage = req.file ? req.file.filename : null;
  const query = `
    INSERT INTO property (
      pName,
      ownerName,
      agentName,
      pType,
      pStatus,
      totalfloor,
      fNo,
      transactionType,
      face,
      typeofowner,
      yearOfConstruction,
      price,
      bookingAmount,
      address,
      city,
      landmark,
      floaring,
      overlooking,
      additionalRoom,
      description,
      pFor,
      images
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `;

  connection.query(
    query,
    [
      PropertyName,
      OwnerName,
      "",
      PropertyType,
      PropertyStatus,
      totalfloor,
      floorNo,
      transactionsType,
      Face,
      TypeOfOwner,
      YearOfConstruction,
      price,
      BookingAmount,
      address,
      city,
      landMark,
      flooring,
      overLooking,
      additionalRoom,
      description,
      propertyAction,
      propertyImage,
    ],
    (err, result) => {
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ message: "Database error", error: err });
      }
      res.json({
        message: "Property registered successfully",
        propertyId: result.insertId,
      });
    }
  );
});

app.get("/admindashboard", (req, res) => {
  const getAllQuery = "SELECT * FROM register";
  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    const agentCount = allResults.filter((user) => user.status === 0).length;
    const adminCount = allResults.filter((user) => user.status === 1).length;
    const agencyCount = allResults.filter((user) => user.status === 2).length;
    const verifiedCount = allResults.filter(
      (user) => Number(user.approval) === 1
    ).length;
    const notVerifiedCount = allResults.filter(
      (user) => Number(user.approval) === 0
    ).length;
    return res.render("admindashboard", {
      allData: allResults,
      agentCount: agentCount,
      adminCount: adminCount,
      agencyCount: agencyCount,
      verifiedCount: verifiedCount,
      notVerifiedCount: notVerifiedCount,
      user: req.session.user,
    });
  });
});
app.get("/getmeetdetail", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Unauthorized access" });
  }
  const agentEmail = req.session.user.fullName;
  const getMeetingsQuery = "SELECT * FROM meet_schedule WHERE agent_name = ?";
  connection.query(getMeetingsQuery, [agentEmail], (err, meetResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    return res.render("getmeetdetail", {
      meetData: meetResults,
      user: req.session.user,
    });
  });
});
app.get("/download/:fileName", (req, res) => {
  filePath = path.join(uploadDir, req.params.fileName);
  console.log("Checking file at:", filePath);

  if (fs.existsSync(filePath)) {
    return res.download(filePath);
  } else {
    console.error("❌ File not found:", filePath);
    return res.status(404).send("File not found");
  }
});
app.get("/recuriterdashboard", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.redirect("/login");
  }
  const fullName = req.session.user.fullName;
  const query = `SELECT * FROM jobseeker`;
  connection.query(query, (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    const updatedResults = results.map((jobseeker) => {
      if (jobseeker.resume) {
        jobseeker.resume = path.basename(jobseeker.resume);
      }
      return jobseeker;
    });

    res.render("recuriterdashboard", { fullName, jobSeekers: updatedResults });
  });
});

app.get("/jobseekerdata", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.redirect("/adminlogin");
  }
  const fullName = req.session.user.fullName;
  const query = `SELECT * FROM jobseeker`;
  connection.query(query, (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    const updatedResults = results.map((jobseeker) => {
      if (jobseeker.resume) {
        jobseeker.resume = path.basename(jobseeker.resume);
      }
      return jobseeker;
    });

    res.render("jobseekerdata", { fullName, jobSeekers: updatedResults });
  });
});
app.get("/postactivity", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.redirect("/adminlogin");
  }
  const fullName = req.session.user.fullName;
  const getAllQuery = "SELECT * FROM register";
  connection.query(getAllQuery, (err, allResults) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    const agentCount = allResults.filter((user) => user.status === 0).length;
    const adminCount = allResults.filter((user) => user.status === 1).length;
    const agencyCount = allResults.filter((user) => user.status === 2).length;
    const verifiedCount = allResults.filter(
      (user) => Number(user.approval) === 1
    ).length;
    const notVerifiedCount = allResults.filter(
      (user) => Number(user.approval) === 0
    ).length;
    return res.render("postactivity", {
      allData: allResults,
      agentCount,
      adminCount,
      agencyCount,
      verifiedCount,
      notVerifiedCount,
      fullName,
    });
  });
});
app.post("/postactivity", upload.none(), (req, res) => {
  const { organizerName, eventName, eventdate, eventtime, eventrelatedto } =
    req.body;
  if (
    !organizerName ||
    !eventName ||
    !eventdate ||
    !eventtime ||
    !eventrelatedto
  ) {
    return res.status(400).json({ message: "All fields are required" });
  }
  const query = `
    INSERT INTO postactivity (
      organizerName,
      eventName,
      eventdate,
      eventtime,
      eventrelatedto
    ) VALUES (?, ?, ?, ?, ?)
  `;
  connection.query(
    query,
    [organizerName, eventName, eventdate, eventtime, eventrelatedto],
    (err, result) => {
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ message: "Database error", error: err });
      }
      res.json({
        message: "Event posted successfully",
        eventId: result.insertId,
      });
    }
  );
});
app.get("/recuriterdata", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.redirect("/adminlogin");
  }
  const fullName = req.session.user.fullName;
  const query = `SELECT * FROM  recuriter`;
  connection.query(query, (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    const updatedResults = results.map((jobseeker) => {
      if (jobseeker.resume) {
        jobseeker.resume = path.basename(jobseeker.resume);
      }
      return jobseeker;
    });
    res.render("recuriterdata", { fullName, jobSeekers: updatedResults });
  });
});
app.get("/nakuridashboard", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.redirect("/login");
  }

  const fullName = req.session.user.fullName;

  res.render("nakuridashboard", { fullName });
});
app.get("/agencydashboard", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.redirect("/adminlogin");
  }
  const fullName = req.session.user.fullName;
  const query = `
    SELECT 
     *
    FROM meet_schedule m
    JOIN register r ON m.agent_name = r.fullName
    WHERE r.fullName = ?;
  `;

  connection.query(query, [fullName], (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }

    res.render("agencydashboard", {
      fullName: fullName,
      meetings: results,
    });
  });
});
app.get("/agentdashboard", (req, res) => {
  if (!req.session.user || !req.session.user.fullName) {
    return res.redirect("/adminlogin");
  }
  const fullName = req.session.user.fullName;
  console.log("login user full name", fullName);
  const query = `
    SELECT 
     *
    FROM meet_schedule 

    WHERE agent_name = ?;
  `;
  connection.query(query, [fullName], (err, results) => {
    if (err) {
      console.error("Database Error:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    res.render("agentdashboard", {
      fullName: fullName,
      meetings: results,
    });
  });
});
app.post("/meetings", async (req, res) => {
  try {
    const { name, email, pname, aname, meetDate, meetTime } = req.body;
    if (!name || !email || !pname || !aname || !meetDate || !meetTime) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const checkQuery =
      "SELECT * FROM meet_schedule WHERE email_for_meet = ? AND meet_date = ? AND meet_time = ?";
    connection.query(
      checkQuery,
      [email, meetDate, meetTime],
      (err, results) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Database error", error: err });
        }

        if (results.length > 0) {
          console.log("⚠️ Slot already booked");
          return res
            .status(400)
            .json({ message: "User already booked this slot" });
        }
        const pname = req.body.pname;
        const insertQuery =
          "INSERT INTO meet_schedule (contact_person_name, agent_name, pName, email_for_meet, meet_date, meet_time) VALUES (?, ?, ?, ?, ?, ?)";
        connection.query(
          insertQuery,
          [name, aname, pname, email, meetDate, meetTime],
          (err, result) => {
            if (err) {
              return res
                .status(500)
                .json({ message: "Database insert error", error: err });
            }
            res.status(200).json({
              message: "Meeting scheduled successfully",
              redirect: "/login",
            });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});
app.get("/get-agent", (req, res) => {
  const pname = req.query.pname;

  if (!pname) {
    return res.status(400).json({ message: "Property name is required" });
  }
  const agentQuery = "SELECT agentName FROM property WHERE pName = ?";
  connection.query(agentQuery, [pname], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: "No agent found for this property" });
    }

    res.json({ agentName: results[0].agentName });
  });
});
app.post("/updateApproval", (req, res) => {
  const { users } = req.body;

  if (!users || users.length === 0) {
    return res.status(400).json({ message: "No users selected." });
  }
  let updateQueries = users.map((user) => {
    return new Promise((resolve, reject) => {
      const updateQuery = "UPDATE register SET approval = ? WHERE id = ?";
      connection.query(
        updateQuery,
        [user.approvestatus, user.id],
        (err, result) => {
          if (err) reject(err);
          else resolve(result);
        }
      );
    });
  });
  Promise.all(updateQueries)
    .then(() => res.json({ message: "Approval status updated successfully." }))
    .catch((err) => {
      console.error("Database update error:", err);
      res.status(500).json({ message: "Database error", error: err });
    });
});
app.post("/updatePropertyCurrentStatus", (req, res) => {
  const { users } = req.body;

  if (!users || users.length === 0) {
    return res.status(400).json({ message: "No  selection." });
  }
  let updateQueries = users.map((user) => {
    return new Promise((resolve, reject) => {
      const updateQuery =
        "UPDATE meet_schedule SET current_status = ? WHERE id = ?";
      connection.query(
        updateQuery,
        [user.approvestatus, user.id],
        (err, result) => {
          if (err) reject(err);
          else resolve(result);
        }
      );
    });
  });
  Promise.all(updateQueries)
    .then(() => res.json({ message: "Approval status updated successfully." }))
    .catch((err) => {
      console.error("Database update error:", err);
      res.status(500).json({ message: "Database error", error: err });
    });
});
app.post("/updatePropertyapprovalStatus", (req, res) => {
  const { users } = req.body;
  if (!users || users.length === 0) {
    return res.status(400).json({ message: "No  selection." });
  }
  let updateQueries = users.map((user) => {
    return new Promise((resolve, reject) => {
      const updateQuery = "UPDATE property SET approve = ? WHERE id = ?";
      connection.query(
        updateQuery,
        [user.approvestatus, user.id],
        (err, result) => {
          if (err) reject(err);
          else resolve(result);
        }
      );
    });
  });
  Promise.all(updateQueries)
    .then(() => res.json({ message: "Approval status updated successfully." }))
    .catch((err) => {
      console.error("Database update error:", err);
      res.status(500).json({ message: "Database error", error: err });
    });
});
app.post("/mail", function (req, res) {
  let mailtransporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "shefalisethiya90@gmail.com",
      pass: "hwot nehp wyvd idhv",
    },
  });
  let maildetails = {
    from: req.body.from,
    to: req.body.to,
    subject: "OTP Verification",
    text: `Your OTP is: ${req.body.otp.toString()}`,
  };
  mailtransporter.sendMail(maildetails, function (err, data) {
    if (err) {
      console.error("Error sending mail:", err);
      res.status(500).json({ success: false, error: err.message });
    } else {
      res.json({
        success: true,
        message: "Mail sent!",
        redirect: "/otpverify",
      });
    }
  });
});
app.post("/jobseekerregister", upload.single("resume"), (req, res) => {
  try {
    const { fullName, email, mobileNo, currentCity, workstatus } = req.body;
    const resumePath = req.file ? req.file.path : null;

    if (!fullName || !email || !mobileNo || !currentCity || !workstatus) {
      return res.status(400).json({ message: "All fields are required" });
    }
    connection.query(
      "SELECT * FROM jobseeker WHERE email = ? OR mobileNo = ?",
      [email, mobileNo],
      (err, results) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Database error", error: err });
        }
        if (results.length > 0) {
          return res.status(400).json({ message: "User already exists" });
        }
        connection.query(
          "INSERT INTO jobseeker (fullName, email, mobileNo, workStatus, currentCity, resume) VALUES (?, ?, ?, ?, ?, ?)",
          [fullName, email, mobileNo, workstatus, currentCity, resumePath],
          (err, result) => {
            if (err) {
              console.error("Error inserting user:", err);
              return res
                .status(500)
                .json({ message: "Error registering user", error: err });
            }
            if (
              req.headers.accept &&
              req.headers.accept.includes("text/html")
            ) {
              return res.redirect("/hiring");
            } else {
              return res.status(200).json({
                message: "User registered successfully",
                redirect: "/nakuridashboard",
              });
            }
          }
        );
      }
    );
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});
app.post("/recruiterregister", upload.single("resume"), (req, res) => {
  try {
    const { fullName, email, mobileNo, currentCity, nameoforganization } =
      req.body;
    const resumePath = req.file ? req.file.path : null;

    if (
      !fullName ||
      !email ||
      !mobileNo ||
      !currentCity ||
      !nameoforganization
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }
    connection.query(
      "SELECT * FROM recuriter WHERE email = ? OR mobileNo = ?",
      [email, mobileNo],
      (err, results) => {
        if (err) {
          console.error("Database error:", err);
          return res
            .status(500)
            .json({ message: "Database error", error: err });
        }

        if (results.length > 0) {
          return res.status(400).json({ message: "User already exists" });
        }
        connection.query(
          "INSERT INTO recuriter (fullName, email, mobileNo, organizationName, currentCity,logo) VALUES (?, ?, ?, ?, ?, ?)",
          [
            fullName,
            email,
            mobileNo,
            nameoforganization,
            currentCity,
            resumePath,
          ],
          (err, result) => {
            if (err) {
              return res
                .status(500)
                .json({ message: "Error registering user", error: err });
            }
            if (
              req.headers.accept &&
              req.headers.accept.includes("text/html")
            ) {
              return res.redirect("/hiring");
            } else {
              return res.status(200).json({
                message: "User registered successfully",
                redirect: "/nakuridashboard",
              });
            }
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/searchproperty", async (req, res) => {
  console.log("api hitted");
  try {
    const { city } = req.body;
    if (!city) {
      return res.render("index", {
        propertyData: [],
        error: "City is required",
      });
    }
    connection.query(
      "SELECT * FROM property WHERE city = ?",
      [city],
      (err, results) => {
        console.log("Fetched result:", results);
        if (err) {
          console.error("Database error:", err);
        }
        return res.render("index", {
          propertyData: [],
          error: "Database error",
        });
        res.render("index", { propertyData: results, error: null });
      }
    );
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).render("index", {
      propertyData: [],
      error: "Server error",
    });
  }
});
app.post("/submitMaterial", upload.single("uploadImage"), async (req, res) => {
  try {
    const {
      materialName,
      category,
      price,
      unit,
      quantity,
      description,
      supplier,
      location,
    } = req.body;
    const imageFilename = req.file ? req.file.filename : null;
    const insertQuery = `
      INSERT INTO building_materials (
        materialName,
        category,
        price,
        unit,
        quantity,
        description,
        supplier,
        location,
        imageFilename
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    console.log("Raw query result:", insertQuery);
    const [result] = await connection
      .promise()
      .execute(insertQuery, [
        materialName,
        category,
        price,
        unit,
        quantity,
        description,
        supplier,
        location,
        imageFilename,
      ]);
    console.log("Inserted material with ID:", result.insertId);
    res.send(`
      <h2>Material Registered Successfully!</h2>
      <p>Inserted ID: ${result.insertId}</p>
      <p><a href="/index.html">Go Back</a></p>
    `);
  } catch (error) {
    console.error("Error inserting material:", error);
    res.status(500).send("Server Error");
  }
});
app.post(
  "/submitMaintenanceProvider",
  upload.single("uploadFile"),
  async (req, res) => {
    try {
      const {
        providerName,
        companyName,
        email,
        phone,
        serviceCategory,
        serviceArea,
        experience,
        description,
      } = req.body;

      const fileName = req.file ? req.file.filename : null;
      const query = `
      INSERT INTO maintenance_providers (
        providerName,
        companyName,
        email,
        phone,
        serviceCategory,
        serviceArea,
        experience,
        description,
        fileName
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
      const [result] = await connection
        .promise()
        .execute(query, [
          providerName,
          companyName,
          email,
          phone,
          serviceCategory,
          serviceArea,
          experience,
          description,
          fileName,
        ]);
      console.log("Inserted provider with ID:", result.insertId);
      res.send(`
      <h2>Provider Registered Successfully!</h2>
      <p>Inserted ID: ${result.insertId}</p>
      <p><a href="/index.html">Go Back</a></p>
    `);
    } catch (error) {
      console.error("Error inserting provider:", error);
      res.status(500).send("Server Error");
    }
  }
);
app.post(
  "/submitFinanceService",
  upload.single("uploadCertificate"),
  async (req, res) => {
    try {
      const {
        providerName,
        companyName,
        email,
        phone,
        serviceType,
        experience,
        description,
      } = req.body;
      const certificateFilename = req.file ? req.file.filename : null;
      const insertQuery = `
      INSERT INTO finance_service_providers (
        providerName,
        companyName,
        email,
        phone,
        serviceType,
        experience,
        description,
        certificateFilename
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
      const [result] = await connection
        .promise()
        .query(insertQuery, [
          providerName,
          companyName,
          email,
          phone,
          serviceType,
          experience,
          description,
          certificateFilename,
        ]);
      console.log(
        "Inserted finance service provider with ID:",
        result.insertId
      );
      res.send(`
      <h2>Finance Service Provider Registered Successfully!</h2>
      <p>Inserted ID: ${result.insertId}</p>
      <p><a href="/index.html">Go Back</a></p>
    `);
    } catch (error) {
      console.error("Error inserting finance service provider:", error);
      res.status(500).send("Server Error");
    }
  }
);
app.post("/submitBooking", async (req, res) => {
  try {
    const {
      fullName,
      email,
      phone,
      serviceType,
      bookingDate,
      propertyAddress,
      comments,
    } = req.body;
    const insertQuery = `
      INSERT INTO service_bookings (
        fullName,
        email,
        phone,
        serviceType,
        bookingDate,
        propertyAddress,
        comments
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    const [result] = await await connection
      .promise()
      .query(insertQuery, [
        fullName,
        email,
        phone,
        serviceType,
        bookingDate,
        propertyAddress,
        comments,
      ]);
    console.log("Inserted booking with ID:", result.insertId);
    res.send(`
      <h2>Booking Submitted Successfully!</h2>
      <p>Booking ID: ${result.insertId}</p>
      <p><a href="/bookingForm.html">Go Back</a></p>
    `);
  } catch (error) {
    console.error("Error inserting booking:", error);
    res.status(500).send("Server Error");
  }
});
app.post("/Contact", (req, res) => {
  const { userName, userEmail, subject, message } = req.body;
  console.log("contact api hitted:req.body:", req.body);
  const sql =
    "INSERT INTO contact (userName, userEmail, subject, message) VALUES (?, ?, ?, ?)";
  connection.query(
    sql,
    [userName, userEmail, subject, message],
    (err, result) => {
      if (err) {
        console.error("Error inserting data: ", err);
        return res.status(500).send("Error saving data.");
      }
      console.log("Data inserted successfully:", result);
      res.send(`
      <h2>Thank you, ${userName}!</h2>
      <p>Your message has been received.</p>
      <p><strong>Email:</strong> ${userEmail}</p>
      <p><strong>Subject:</strong> ${subject}</p>
      <p><strong>Message:</strong> ${message}</p>
      <a href="/">Go Back</a>
    `);
    }
  );
});
app.get("/getContactdata", (req, res) => {
  const sql = "SELECT * FROM contact";
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      return res.status(500).send("Error fetching contact details.");
    }
    res.render("contact", { contacts: results });
  });
});
app.get("/getproperties", (req, res) => {
  const sql = "SELECT * FROM property";

  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      return res
        .status(500)
        .json({ error: "Error fetching property details." });
    }
    res.json(results);
  });
});
app.get("/get-maintenance-providers", (req, res) => {
  const sql = "SELECT * FROM maintenance_providers";
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      return res
        .status(500)
        .json({ error: "Error fetching maintenance providers." });
    }
    res.json(results);
  });
});
app.get("/get-post-activities", (req, res) => {
  const sql = "SELECT * FROM postactivity";
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching data:", err);
      return res.status(500).json({ error: "Error fetching post activities." });
    }
    res.json(results);
  });
});
app.post("/post-job", (req, res) => {
  const { title, company, description, location, category, deadline, salary } =
    req.body;
  if (
    !title ||
    !company ||
    !description ||
    !location ||
    !category ||
    !deadline ||
    !salary
  ) {
    return res.status(400).json({ error: "All fields are required" });
  }
  const sql =
    "INSERT INTO jobs (title, company, description, location, category, deadline, salary) VALUES (?, ?, ?, ?, ?, ?, ?)";
  connection.query(
    sql,
    [title, company, description, location, category, deadline, salary],
    (err, result) => {
      if (err) {
        console.error("Error inserting job:", err);
        return res.status(500).json({ error: "Error saving job data" });
      }
      res
        .status(200)
        .json({ message: "Job posted successfully", jobId: result.insertId });
    }
  );
});
app.get("/jobs", (req, res) => {
  const sql = "SELECT * FROM jobs";
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching jobs:", err);
      return res.status(500).json({ error: "Error retrieving job listings" });
    }
    res.status(200).json(results);
  });
});
app.get("/propertyforrent", (req, res) => {
  const sql = "SELECT * FROM property WHERE pFor = 'Rent'";
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching jobs:", err);
      return res.status(500).json({ error: "Error retrieving job listings" });
    }
    res.status(200).json(results);
  });
});
app.get("/propertyforsell", (req, res) => {
  const sql = "SELECT * FROM property WHERE pFor = 'sell'";
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching jobs:", err);
      return res.status(500).json({ error: "Error retrieving job listings" });
    }
    res.status(200).json(results);
  });
});
app.get("/propertyforexchange", (req, res) => {
  const sql = "SELECT * FROM property WHERE pFor = 'exchange'";
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching jobs:", err);
      return res.status(500).json({ error: "Error retrieving job listings" });
    }
    res.status(200).json(results);
  });
});
app.get("/propertybycity", (req, res) => {
  const city = req.body.city;
  const sql = "SELECT * FROM property WHERE city = ?";
  connection.query(sql, [city], (err, results) => {
    if (err) {
      console.error("Error fetching properties:", err);
      return res.status(500).json({ error: "Error retrieving properties" });
    }
    res.status(200).json(results);
  });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Server running at http://0.0.0.0:${port}/`);
});
