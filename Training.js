const { connectDb_dev } = require("./database");

async function getDesignations() {
  let connection;

  try {
    connection = await connectDb_dev();
    const result = await connection.execute(
      `SELECT EPDMBE_GROUP_DESG_NAME  FROM trs.EPDMBE_GROUP_DESG`,
      [],
      { outFormat: require("oracledb").OUT_FORMAT_OBJECT }
    );

    return result.rows;
  } catch (error) {
    console.error("Error fetching designations:", error);
    throw error;
  } finally {
    if (connection) {
      await connection.close();
    }
  }
}

module.exports = { getDesignations };
