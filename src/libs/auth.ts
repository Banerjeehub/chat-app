import { NextAuthOptions, getServerSession } from "next-auth";
import { UpstashRedisAdapter } from "@next-auth/upstash-redis-adapter";
import { db } from "./db";
import GoogleProvider from "next-auth/providers/google";

function getGoogleCredentials() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

  if (!clientId || clientId.length === 0) {
    throw new Error("Client id does not exist");
  }
  if (!clientSecret || clientSecret.length === 0) {
    throw new Error("Client Secret does not exist");
  }

  return { clientId, clientSecret };
}

export const authOptions: NextAuthOptions = {
  adapter: UpstashRedisAdapter(db),
  session: {
    strategy: "jwt",
  },
  pages: {
    signIn: "/login",
  },
  providers: [
    GoogleProvider({
      clientId: getGoogleCredentials().clientId,
      clientSecret: getGoogleCredentials().clientSecret,
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // Ensure token.id or user.id exists before trying to fetch from Redis
      const userId = token.id || (user && user.id);

      if (!userId) {
        // If no user ID is present in token or user, return the token as is
        return token;
      }

      const existingUser = (await db.get(`user:${userId}`)) as User | null;

      if (!existingUser) {
        // If user data is not found in Redis and user is present (initial sign-in), set the token id
        if (user) {
          token.id = user.id;
        }
      } else {
        // If user data is found, update the token with user data
        token = {
          id: existingUser.id,
          name: existingUser.name,
          email: existingUser.email,
          picture: existingUser.image, // Correct property name should be picture
        };
      }

      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id;
        session.user.name = token.name;
        session.user.email = token.email;
        session.user.image = token.picture; // Ensure this matches the jwt callback's property
      }

      return session;
    },
    redirect() {
      return "/dashboard";
    },
  },
};

// export const getAuthSession = () => getServerSession(authOptions);
