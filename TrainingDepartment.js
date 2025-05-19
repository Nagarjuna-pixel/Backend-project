const { connectDb_dev } = require("./database");

async function getDepartment() {
  let connection;

  try {
    connection = await connectDb_dev();
    const result = await connection.execute(
      `SELECT EPDMBA_DEPT_LNAME FROM trs.EPDMBA_DEPARTMENT`,
      [],
      { outFormat: require("oracledb").OUT_FORMAT_OBJECT }
    );

    return result.rows;
  } catch (error) {
    console.error("Error fetching departments:", error);
    throw error;
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}

module.exports = { getDepartment };