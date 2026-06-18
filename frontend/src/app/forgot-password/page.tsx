import { AuthPage } from "@/components/auth-page";
import { Suspense } from "react";

export default function ForgotPasswordPage() {
  return (
    <Suspense fallback={null}>
      <AuthPage mode="forgot" />
    </Suspense>
  );
}
