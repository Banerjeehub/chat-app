import Button from "@/components/ui/Button";
import { authOptions } from "@/libs/auth";
import { getServerSession } from "next-auth";

const page = async () => {
  const session = await getServerSession(authOptions);

  return <pre>{JSON.stringify(session)}</pre>;
};

export default page;
