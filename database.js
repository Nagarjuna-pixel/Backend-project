const oracledb = require("oracledb");
// oracledb.initOracleClient({ libDir: "C:\\instantclient_21_11" });
oracledb.initOracleClient({ libDir: "E:\\instantclient" });
const connectDb_dev = async () => {
  const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    connectString: process.env.DB_CONNECTSTRING,
  };

  try {
    const connection = await oracledb.getConnection(dbConfig);

    return connection;
  } catch (err) {
    console.error("Error connecting to the database:", err);
    throw err; // Propagate the error to the caller
  }
};

module.exports = {
    connectDb_dev,
   
  };
  