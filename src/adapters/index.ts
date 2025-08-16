// Database adapters entry point - import only what you need
export { mongoAdapter, createMongoAdapter, configureMongoAdapter, parseMongoUri, healthCheckMongo } from "./mongo";
export { createPrismaAdapter as prismaAdapter } from "./prisma";
