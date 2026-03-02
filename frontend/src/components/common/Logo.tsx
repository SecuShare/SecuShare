// Copyright (c) 2026 Mounir IDRASSI
// Affiliation: AM Crypto (https://amcrypto.jp)
// License: MIT

interface LogoProps {
  size?: 'sm' | 'md';
}

export function Logo({ size = 'md' }: LogoProps) {
  const px = size === 'sm' ? 'w-6 h-6' : 'w-10 h-10';
  const logoUrl = `${import.meta.env.BASE_URL}logo.svg`;
  return <img src={logoUrl} alt="" aria-hidden="true" className={px} />;
}
