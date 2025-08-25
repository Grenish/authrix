import { parentPort } from "worker_threads";
import * as bcrypt from "bcryptjs";
import * as argon2 from "argon2";
import { randomBytes } from "crypto";

interface WorkerMessage {
  id: string;
  type: "hash" | "verify";
  password: string;
  algorithm?: "bcrypt" | "argon2id";
  hash?: string;
  options?: {
    bcryptRounds?: number;
    argon2Options?: {
      timeCost: number;
      memoryCost: number;
      parallelism: number;
      saltLength: number;
    };
  };
}

interface WorkerResponse {
  id: string;
  success: boolean;
  result?: string | boolean;
  error?: string;
}

if (parentPort) {
  parentPort.on("message", async (message: WorkerMessage) => {
    const response: WorkerResponse = {
      id: message.id,
      success: false,
    };

    try {
      switch (message.type) {
        case "hash": {
          if (message.algorithm === "bcrypt") {
            const rounds = message.options?.bcryptRounds || 14;
            response.result = await bcrypt.hash(message.password, rounds);
          } else {
            const options = message.options?.argon2Options || {
              timeCost: 3,
              memoryCost: 65536,
              parallelism: 4,
              saltLength: 16,
            };

            response.result = await argon2.hash(message.password, {
              type: argon2.argon2id,
              timeCost: options.timeCost,
              memoryCost: options.memoryCost,
              parallelism: options.parallelism,
              salt: randomBytes(options.saltLength),
            });
          }
          response.success = true;
          break;
        }

        case "verify": {
          if (!message.hash) {
            throw new Error("Hash is required for verification");
          }

          if (message.hash.startsWith("$2")) {
            response.result = await bcrypt.compare(
              message.password,
              message.hash
            );
          } else if (message.hash.startsWith("$argon2")) {
            response.result = await argon2.verify(
              message.hash,
              message.password
            );
          } else {
            throw new Error("Unsupported hash format");
          }
          response.success = true;
          break;
        }

        default:
          throw new Error(`Unknown operation type: ${message.type}`);
      }
    } catch (error) {
      response.success = false;
      response.error = error instanceof Error ? error.message : "Unknown error";
    }

    parentPort!.postMessage(response);
  });
}
