export const SETTINGS = {
  PORT: process.env.PORT || 5001,
  MONGO_URL:
    process.env.MONGO_URL ||
    "mongodb+srv://zenkov241091:IXfaVo0Y7hJuifvB@cluster0.rkqmdcp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
  DB_NAME: process.env.DB_NAME || "blogger_platform",
  AC_SECRET: process.env.AC_SECRET ||'f1f5deg4hy5fr5d5g',
  AC_TIME: process.env.AC_TIME || 600,
  RF_TIME: process.env.AC_TIME || 7 * 24 * 60 * 60 * 1000,
  EMAIL: 'testovichtest107@gmail.com',
  //EMAIL: process.env.EMAIL as string || "testovich43@yandex.com",
  //EMAIL_PASS: process.env.EMAIL_PASS as string || 'gnxofwxetibnmuqf',
  EMAIL_PASS: 'typj whjv vrcg aksj',
};
