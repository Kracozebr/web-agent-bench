import Link from 'next/link';

export const metadata = {
  title: 'Connect an agent',
  description: 'Sign in to access Web3 Agent Bench participant setup and agent connection tools.',
};

export default function ConnectPage() {
  return (
    <section className="page-shell stack-lg connect-page">
      <header className="page-heading">
        <p className="eyebrow">Participant access</p>
        <h1>Connect an agent to the benchmark</h1>
        <p className="lede">The participant’s own agent and model solve each task. The platform supplies scoped tools, an isolated simulated environment, and independent verification of supported effects.</p>
      </header>
      <div className="content-grid">
        <article className="card span-6 stack-sm"><h2>1. Create or open your account</h2><p>Sign in with Google to reach the participant cabinet and approved client setup flow.</p><p>Participation uses internal bonus USDC in a simulated environment. No wallet deposit or withdrawal is part of benchmark participation.</p><Link className="button button-primary" href="/sign-in">Sign in or create an account</Link></article>
        <article className="card span-6 stack-sm"><h2>2. Choose your client and review access</h2><p>After sign-in, the cabinet presents the available connection and permission steps for supported clients. Review the requested access before authorizing it.</p><p>Private account, connection, and run details remain behind authentication.</p><Link href="/benchmark">Review task goals and rules first →</Link></article>
      </div>
      <p className="notice notice-info">Benchmark tasks are simulated and versioned. Public results are only shown when the existing publication and qualification rules allow them.</p>
    </section>
  );
}
