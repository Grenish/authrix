import type { AuthDbAdapter, AuthUser } from "../types/db";
import { initializeApp, getApps, FirebaseApp } from "firebase/app";
import { 
  getFirestore, 
  Firestore, 
  collection, 
  doc, 
  getDoc, 
  setDoc, 
  query, 
  where, 
  getDocs 
} from "firebase/firestore";

// Firebase config from environment
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
};

const COLLECTION_NAME = process.env.FIREBASE_AUTH_COLLECTION || "users";

// Initialize Firebase
let app: FirebaseApp;
if (getApps().length === 0) {
  app = initializeApp(firebaseConfig);
} else {
  app = getApps()[0];
}

const db: Firestore = getFirestore(app);

export const firebaseAdapter: AuthDbAdapter = {
  async findUserByEmail(email: string): Promise<AuthUser | null> {
    try {
      const normalizedEmail = email.toLowerCase().trim();
      const usersRef = collection(db, COLLECTION_NAME);
      const q = query(usersRef, where("email", "==", normalizedEmail));
      const querySnapshot = await getDocs(q);

      if (querySnapshot.empty) return null;

      const userData = querySnapshot.docs[0].data();
      const docId = querySnapshot.docs[0].id;

      return {
        id: docId,
        email: userData.email,
        password: userData.password,
        createdAt: userData.createdAt?.toDate(),
      };
    } catch (error) {
      console.error("Error finding user by email:", error);
      return null;
    }
  },

  async findUserById(id: string): Promise<AuthUser | null> {
    try {
      const userRef = doc(db, COLLECTION_NAME, id);
      const userSnap = await getDoc(userRef);

      if (!userSnap.exists()) return null;

      const userData = userSnap.data();

      return {
        id: userSnap.id,
        email: userData.email,
        password: userData.password,
        createdAt: userData.createdAt?.toDate(),
      };
    } catch (error) {
      console.error("Error finding user by ID:", error);
      return null;
    }
  },

  async createUser({ email, password }): Promise<AuthUser> {
    try {
      const normalizedEmail = email.toLowerCase().trim();
      const now = new Date();
      
      // Generate a new document reference to get the ID
      const userRef = doc(collection(db, COLLECTION_NAME));
      
      const userData = {
        email: normalizedEmail,
        password,
        createdAt: now,
      };

      await setDoc(userRef, userData);

      return {
        id: userRef.id,
        email: normalizedEmail,
        password,
        createdAt: now,
      };
    } catch (error) {
      console.error("Error creating user:", error);
      throw new Error(`Failed to create user: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  },
};
