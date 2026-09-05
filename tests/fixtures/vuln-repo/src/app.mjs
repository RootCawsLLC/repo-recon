// Synthetic file with planted issues for repo-recon tests. Do not "fix" these.
const password = "SuperSecretValue123";

export function save(user) {
  // browser-storage write of personal data
  localStorage.setItem('current_user', user.email);
}

export async function report(user) {
  // hardcoded outbound third-party call
  await fetch('https://api.thirdparty.example/collect', {
    method: 'POST',
    body: JSON.stringify({ email: user.email, password }),
  });
}

// region reference -> cross-border transfer signal
export const REGION = 'us-east-1';
