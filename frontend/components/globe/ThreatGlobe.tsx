"use client";

import { useRef, useMemo, useEffect, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Stars } from "@react-three/drei";
import * as THREE from "three";

interface ThreatOrigin {
  lat: number;
  lng: number;
  count: number;
  country: string;
  severity: "critical" | "high" | "medium";
}

const THREAT_DATA: ThreatOrigin[] = [
  { lat: 39.9042, lng: 116.4074, count: 342, country: "China", severity: "critical" },
  { lat: 55.7558, lng: 37.6173, count: 276, country: "Russia", severity: "critical" },
  { lat: 35.6892, lng: 51.389, count: 128, country: "Iran", severity: "high" },
  { lat: 39.0392, lng: 125.7625, count: 95, country: "N. Korea", severity: "high" },
  { lat: -15.7975, lng: -47.8919, count: 67, country: "Brazil", severity: "medium" },
  { lat: 9.0579, lng: 7.4951, count: 54, country: "Nigeria", severity: "medium" },
  { lat: 21.0278, lng: 105.8342, count: 41, country: "Vietnam", severity: "medium" },
  { lat: 28.6139, lng: 77.209, count: 38, country: "India", severity: "medium" },
  { lat: 44.4268, lng: 26.1025, count: 29, country: "Romania", severity: "medium" },
];

const TARGET = { lat: 38.9072, lng: -77.0369 }; // Washington DC

function latLngToVec3(lat: number, lng: number, radius: number): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lng + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  );
}

function GlobeWireframe() {
  const ref = useRef<THREE.Mesh>(null);
  useFrame((_, delta) => {
    if (ref.current) ref.current.rotation.y += delta * 0.05;
  });
  return (
    <mesh ref={ref}>
      <sphereGeometry args={[2, 32, 32]} />
      <meshBasicMaterial color="#0a0e1a" transparent opacity={0.9} />
      <lineSegments>
        <edgesGeometry args={[new THREE.SphereGeometry(2.01, 24, 24)]} />
        <lineBasicMaterial color="#00ffd5" transparent opacity={0.12} />
      </lineSegments>
    </mesh>
  );
}

function ThreatPoints() {
  const ref = useRef<THREE.Group>(null);
  useFrame((_, delta) => {
    if (ref.current) ref.current.rotation.y += delta * 0.05;
  });

  return (
    <group ref={ref}>
      {THREAT_DATA.map((t, i) => {
        const pos = latLngToVec3(t.lat, t.lng, 2.05);
        const color = t.severity === "critical" ? "#ff2d55" : t.severity === "high" ? "#ff6b35" : "#00ffd5";
        const size = 0.02 + (t.count / 400) * 0.04;
        return (
          <mesh key={i} position={pos}>
            <sphereGeometry args={[size, 8, 8]} />
            <meshBasicMaterial color={color} />
            <pointLight color={color} intensity={0.3} distance={0.5} />
          </mesh>
        );
      })}
    </group>
  );
}

function AttackArcs() {
  const groupRef = useRef<THREE.Group>(null);
  const [phase, setPhase] = useState(0);

  useFrame((_, delta) => {
    if (groupRef.current) groupRef.current.rotation.y += delta * 0.05;
    setPhase((p) => (p + delta * 0.5) % 1);
  });

  const arcs = useMemo(() => {
    const targetPos = latLngToVec3(TARGET.lat, TARGET.lng, 2.05);
    return THREAT_DATA.map((t) => {
      const srcPos = latLngToVec3(t.lat, t.lng, 2.05);
      const mid = srcPos.clone().add(targetPos).multiplyScalar(0.5);
      mid.normalize().multiplyScalar(3.5 + t.count / 200);

      const curve = new THREE.QuadraticBezierCurve3(srcPos, mid, targetPos);
      const points = curve.getPoints(40);
      const color = t.severity === "critical" ? "#ff2d55" : t.severity === "high" ? "#ff6b35" : "#00ffd5";
      return { points, color };
    });
  }, []);

  return (
    <group ref={groupRef}>
      {arcs.map((arc, i) => (
        <line key={i}>
          <bufferGeometry>
            <bufferAttribute
              attach="attributes-position"
              count={arc.points.length}
              array={new Float32Array(arc.points.flatMap((p) => [p.x, p.y, p.z]))}
              itemSize={3}
            />
          </bufferGeometry>
          <lineBasicMaterial color={arc.color} transparent opacity={0.4} />
        </line>
      ))}
    </group>
  );
}

function TargetPoint() {
  const ref = useRef<THREE.Group>(null);
  const pos = latLngToVec3(TARGET.lat, TARGET.lng, 2.05);

  useFrame((state, delta) => {
    if (ref.current) ref.current.rotation.y += delta * 0.05;
  });

  return (
    <group ref={ref}>
      <mesh position={pos}>
        <sphereGeometry args={[0.04, 12, 12]} />
        <meshBasicMaterial color="#00ff88" />
        <pointLight color="#00ff88" intensity={0.5} distance={0.8} />
      </mesh>
    </group>
  );
}

export default function ThreatGlobe() {
  return (
    <div className="w-full h-full relative">
      <Canvas
        camera={{ position: [0, 0, 5.5], fov: 45 }}
        style={{ background: "transparent" }}
      >
        <ambientLight intensity={0.1} />
        <Stars radius={50} depth={50} count={1500} factor={3} fade speed={1} />
        <GlobeWireframe />
        <ThreatPoints />
        <AttackArcs />
        <TargetPoint />
        <OrbitControls
          enableZoom={true}
          enablePan={false}
          minDistance={3.5}
          maxDistance={8}
          autoRotate={false}
        />
      </Canvas>
      {/* Legend overlay */}
      <div className="absolute bottom-3 left-3 text-[9px] space-y-1">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-cyber-red" />
          <span className="text-slate-400">Critical Threat Origin</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-cyber-amber" />
          <span className="text-slate-400">High Threat Origin</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-cyber-cyan" />
          <span className="text-slate-400">Medium Threat Origin</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-cyber-green" />
          <span className="text-slate-400">Defense Target (DC)</span>
        </div>
      </div>
    </div>
  );
}
