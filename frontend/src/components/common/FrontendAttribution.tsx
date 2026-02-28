import { Github } from 'lucide-react';

type FrontendAttributionProps = {
  className?: string;
};

export function FrontendAttribution({ className = '' }: FrontendAttributionProps) {
  const wrapperClass = [
    'fixed bottom-3 left-1/2 z-40 w-[calc(100%-1.5rem)] max-w-fit -translate-x-1/2 rounded-full border border-gray-200 bg-white/90 shadow-lg backdrop-blur',
    'md:static md:bottom-auto md:left-auto md:z-auto md:w-full md:max-w-none md:translate-x-0 md:rounded-none md:border-x-0 md:border-b-0 md:border-t md:bg-gradient-to-r md:from-slate-50 md:via-white md:to-indigo-50/50 md:shadow-none md:backdrop-blur-none',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <footer className={wrapperClass}>
      <div className="mx-auto flex w-full max-w-6xl flex-nowrap items-center justify-center gap-4 px-4 py-2 text-xs text-gray-600 md:py-4 md:text-sm">
        <p className="inline-flex items-center gap-1 whitespace-nowrap">
          By{' '}
          <a
            href="https://amcrypto.jp"
            target="_blank"
            rel="noreferrer"
            className="font-medium text-gray-800 hover:text-indigo-700"
          >
            AM Crypto
          </a>
        </p>

        <a
          href="https://github.com/SecuShare/SecuShare"
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 whitespace-nowrap font-medium text-gray-800 hover:text-indigo-700"
        >
          <Github className="h-4 w-4 text-gray-500" />
          Source
        </a>
      </div>
    </footer>
  );
}
