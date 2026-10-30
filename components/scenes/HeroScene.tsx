'use client';

import React, { useRef, useMemo, useState, useEffect } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';

function NodeNetwork() {
  const count = 45;
  const meshRef = useRef<THREE.InstancedMesh>(null);

  // Generate deterministic points around a 3D sphere/cylinder volume
  const [positions] = useMemo(() => {
    const pos = new Float32Array(count * 3);

    for (let i = 0; i < count; i++) {
      const radius = 2.5 + (i % 3) * 0.8;
      const theta = (i / count) * Math.PI * 2;
      const phi = Math.sin(i * 1.5) * 1.2;

      pos[i * 3] = radius * Math.cos(theta);
      pos[i * 3 + 1] = radius * Math.sin(theta) * 0.5 + phi;
      pos[i * 3 + 2] = Math.sin(theta * 2) * 2;
    }
    return [pos];
  }, [count]);

  const dummy = useMemo(() => new THREE.Object3D(), []);

  useFrame((state) => {
    const t = state.clock.getElapsedTime();
    const mouseX = state.pointer.x * 2.5;
    const mouseY = state.pointer.y * 2.5;

    if (meshRef.current) {
      for (let i = 0; i < count; i++) {
        const x = positions[i * 3] + Math.sin(t * 0.4 + i) * 0.15 + mouseX * 0.1;
        const y = positions[i * 3 + 1] + Math.cos(t * 0.5 + i) * 0.15 - mouseY * 0.1;
        const z = positions[i * 3 + 2] + Math.sin(t * 0.3 + i * 2) * 0.1;

        dummy.position.set(x, y, z);
        const scale = 0.05 + Math.sin(t * 2 + i) * 0.02;
        dummy.scale.set(scale, scale, scale);
        dummy.updateMatrix();

        meshRef.current.setMatrixAt(i, dummy.matrix);
      }
      meshRef.current.instanceMatrix.needsUpdate = true;
    }
  });

  return (
    <group>
      <instancedMesh ref={meshRef} args={[undefined, undefined, count]}>
        <sphereGeometry args={[1, 16, 16]} />
        <meshBasicMaterial color="#C6FF3D" transparent opacity={0.65} />
      </instancedMesh>
    </group>
  );
}

export default function HeroScene() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(true);
  const [shouldRender, setShouldRender] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const isMobile = window.innerWidth < 768;
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (isMobile || prefersReduced) {
      setShouldRender(false);
      return;
    }

    setShouldRender(true);

    const el = containerRef.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        setIsVisible(entry.isIntersecting);
      },
      { threshold: 0.05 }
    );

    observer.observe(el);

    return () => {
      observer.disconnect();
    };
  }, []);

  if (!shouldRender) {
    return (
      <div ref={containerRef} className="w-full h-full absolute inset-0 pointer-events-none" />
    );
  }

  return (
    <div ref={containerRef} className="w-full h-full absolute inset-0 pointer-events-none">
      <Canvas
        camera={{ position: [0, 0, 6], fov: 45 }}
        frameloop={isVisible ? 'always' : 'never'}
        gl={{
          alpha: true,
          antialias: false,
          powerPreference: 'high-performance',
        }}
        dpr={[1, 1.25]}
      >
        <ambientLight intensity={0.5} />
        <NodeNetwork />
      </Canvas>
    </div>
  );
}
