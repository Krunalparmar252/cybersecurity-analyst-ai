'use client';

import React, { useRef, useState, useEffect } from 'react';
import { gsap, useGSAP, prefersReducedMotion } from '@/lib/motion';

interface ScrambleIdProps {
  value: string;
  className?: string;
  chars?: string;
  speed?: number;
  triggerOnMount?: boolean;
}

export default function ScrambleId({
  value,
  className = '',
  chars = '0123456789ABCDEFabcdef!@#$%^&*',
  speed = 40,
  triggerOnMount = true,
}: ScrambleIdProps) {
  const [display, setDisplay] = useState(value);
  const elementRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!triggerOnMount || prefersReducedMotion()) {
      setDisplay(value);
      return;
    }

    let iteration = 0;
    const maxIterations = value.length * 2;
    const interval = setInterval(() => {
      setDisplay(
        value
          .split('')
          .map((char, index) => {
            if (index < iteration / 2) {
              return value[index];
            }
            if (char === ' ' || char === '-' || char === ':' || char === '/') return char;
            return chars[Math.floor(Math.random() * chars.length)];
          })
          .join('')
      );

      if (iteration >= maxIterations) {
        clearInterval(interval);
        setDisplay(value);
      }
      iteration += 1;
    }, speed);

    return () => clearInterval(interval);
  }, [value, triggerOnMount, chars, speed]);

  return (
    <span ref={elementRef} className={`font-mono tabular-nums ${className}`}>
      {display}
    </span>
  );
}

