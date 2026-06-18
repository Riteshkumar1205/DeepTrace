import { AuthPage } from "@/components/auth-page";
import { Suspense } from "react";

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={null}>
      <AuthPage mode="reset" />
    </Suspense>
  );
}
