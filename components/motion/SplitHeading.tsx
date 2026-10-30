'use client';

import React, { useRef } from 'react';
import { gsap, useGSAP, prefersReducedMotion } from '@/lib/motion';

interface SplitHeadingProps {
  text: string;
  italicWord?: string;
  as?: 'h1' | 'h2' | 'h3' | 'h4';
  className?: string;
  delay?: number;
}

export default function SplitHeading({
  text,
  italicWord,
  as: Tag = 'h1',
  className = '',
  delay = 0.1,
}: SplitHeadingProps) {
  const containerRef = useRef<HTMLHeadingElement>(null);

  useGSAP(
    () => {
      const container = containerRef.current;
      if (!container) return;

      const words = container.querySelectorAll('.split-word-inner');
      if (words.length === 0) return;

      if (prefersReducedMotion()) {
        gsap.set(words, { y: 0, opacity: 1 });
        return;
      }

      gsap.fromTo(
        words,
        {
          y: '110%',
          opacity: 0,
        },
        {
          y: '0%',
          opacity: 1,
          duration: 0.85,
          delay,
          stagger: 0.05,
          ease: 'signal',
          scrollTrigger: {
            trigger: container,
            start: 'top 85%',
            once: true,
          },
        }
      );
    },
    { scope: containerRef }
  );

  const tokens = text.split(' ');

  return (
    <Tag ref={containerRef} className={`overflow-hidden tracking-tight leading-[1.08] ${className}`}>
      {tokens.map((word, i) => {
        // Strip punctuation for matching italicWord
        const cleanWord = word.replace(/[.,/#!$%^&*;:{}=\-_`~()]/g, '');
        const isItalic = italicWord && cleanWord.toLowerCase() === italicWord.toLowerCase();

        return (
          <span key={i} className="inline-block overflow-hidden mr-[0.26em] align-top">
            <span
              className={`split-word-inner inline-block ${
                isItalic
                  ? 'font-serif italic font-normal tracking-normal text-text-primary px-[0.05em]'
                  : ''
              }`}
              style={{ willChange: 'transform' }}
            >
              {word}
            </span>
          </span>
        );
      })}
    </Tag>
  );
}

