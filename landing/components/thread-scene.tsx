"use client";

import { useEffect, useMemo, useRef } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

/* ------------------------------------------------------------------ *
 * The signature: a thread/node network whose state is driven by page
 * scroll. Three module nodes joined by one thread — a spider's web, and
 * a diagram of the product (see DESIGN.md §7). Runs as a fixed background
 * layer behind all content.
 * ------------------------------------------------------------------ */

const COL_THREAD = new THREE.Color("#c81e3a");
const COL_BRIGHT = new THREE.Color("#e23150");
const COL_NODE = new THREE.Color("#7d7c84");
const COL_MODULE = new THREE.Color("#b8b7bd");

// Small deterministic PRNG so node positions are stable across renders.
function mulberry32(seed: number) {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const clamp01 = (x: number) => Math.min(1, Math.max(0, x));
function smoothstep(e0: number, e1: number, x: number) {
  const t = clamp01((x - e0) / (e1 - e0));
  return t * t * (3 - 2 * t);
}

type PhaseState = {
  fracture: number; // 0..1 how far nodes have drifted apart
  weave: number; // 0..1 thread opacity target
  focus: number; // -1 none, else module index 0..2
  focusStrength: number; // 0..1
  contract: number; // 0..1 footer resolve
  opacity: number; // global fade
};

// Narrative phases keyed off scroll progress (0..1). Mirrors DESIGN.md §1.
function phaseFromProgress(p: number): PhaseState {
  // fracture rises during The Fracture, falls as The Thread reweaves.
  const fracture =
    smoothstep(0.14, 0.24, p) * (1 - smoothstep(0.3, 0.4, p));

  // threads: faint in hero, decay in fracture, draw in The Thread, hold after.
  const heroBase = 0.16 * (1 - smoothstep(0.12, 0.18, p));
  const decay = 1 - fracture;
  const drawn = smoothstep(0.3, 0.44, p) * 0.82;
  const weave = Math.max(heroBase * decay, drawn) * (1 - 0.85 * smoothstep(0.9, 1, p));

  // module focus across 0.44..0.74, one node each.
  let focus = -1;
  let focusStrength = 0;
  if (p >= 0.44 && p < 0.74) {
    const local = (p - 0.44) / 0.3; // 0..1 across three modules
    focus = Math.min(2, Math.floor(local * 3));
    const within = local * 3 - focus; // 0..1 inside this module
    focusStrength = Math.sin(within * Math.PI); // ease in/out, peak mid
  }

  const contract = smoothstep(0.88, 1, p);
  const opacity = 1 - 0.8 * contract;

  return { fracture, weave, focus, focusStrength, contract, opacity };
}

function softCircleTexture(): THREE.Texture {
  const s = 64;
  const cv = document.createElement("canvas");
  cv.width = cv.height = s;
  const ctx = cv.getContext("2d")!;
  const g = ctx.createRadialGradient(s / 2, s / 2, 0, s / 2, s / 2, s / 2);
  g.addColorStop(0, "rgba(255,255,255,1)");
  g.addColorStop(0.35, "rgba(255,255,255,0.85)");
  g.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, s, s);
  const tex = new THREE.CanvasTexture(cv);
  tex.needsUpdate = true;
  return tex;
}

function Network({ progressRef }: { progressRef: React.MutableRefObject<number> }) {
  const group = useRef<THREE.Group>(null);
  const pointer = useRef({ x: 0, y: 0 });
  const { size } = useThree();

  const model = useMemo(() => {
    const rand = mulberry32(0x5eed);
    const R = 2.35;
    const primaries = [0, 1, 2].map((i) => {
      const a = (i / 3) * Math.PI * 2 - Math.PI / 2;
      return new THREE.Vector3(Math.cos(a) * R, Math.sin(a) * R, 0);
    });
    const center = new THREE.Vector3(0, 0, 0);
    // index 0 = center, 1..3 = module nodes, 4.. = secondary web nodes
    const base: THREE.Vector3[] = [center, ...primaries];
    const SEC = 15;
    for (let i = 0; i < SEC; i++) {
      const a = rand() * Math.PI * 2;
      const r = 1.15 + rand() * 2.7;
      const z = (rand() - 0.5) * 1.7;
      base.push(new THREE.Vector3(Math.cos(a) * r, Math.sin(a) * r, z));
    }

    const edges: [number, number][] = [
      [1, 2],
      [2, 3],
      [3, 1], // the connecting thread between the three modules
      [0, 1],
      [0, 2],
      [0, 3], // hub to each module
    ];
    // each secondary node joins its nearest anchor (center or a module)
    for (let s = 4; s < base.length; s++) {
      let best = 0;
      let bd = Infinity;
      for (let t = 0; t < 4; t++) {
        const d = base[s].distanceToSquared(base[t]);
        if (d < bd) {
          bd = d;
          best = t;
        }
      }
      edges.push([s, best]);
    }

    // explode direction: outward from origin + jitter
    const dirs = base.map((v, i) => {
      if (i === 0) return new THREE.Vector3(0, 0, 0);
      const out = v.clone().normalize();
      out.add(
        new THREE.Vector3(rand() - 0.5, rand() - 0.5, rand() - 0.5).multiplyScalar(
          0.5,
        ),
      );
      return out.multiplyScalar(0.9 + rand() * 0.7);
    });

    // per-node phase for breathing
    const phase = base.map(() => rand() * Math.PI * 2);
    return { base, edges, dirs, phase, moduleIndex: [1, 2, 3] };
  }, []);

  const nodeCount = model.base.length;
  const edgeCount = model.edges.length;

  const tex = useMemo(softCircleTexture, []);

  // geometries built once, mutated per frame
  const { points, lines, nodePos, nodeCol, nodeSize, linePos, lineCol } =
    useMemo(() => {
      const nodePos = new Float32Array(nodeCount * 3);
      const nodeCol = new Float32Array(nodeCount * 3);
      const nodeSize = new Float32Array(nodeCount);
      const linePos = new Float32Array(edgeCount * 2 * 3);
      const lineCol = new Float32Array(edgeCount * 2 * 3);

      const pGeo = new THREE.BufferGeometry();
      pGeo.setAttribute("position", new THREE.BufferAttribute(nodePos, 3));
      pGeo.setAttribute("color", new THREE.BufferAttribute(nodeCol, 3));
      pGeo.setAttribute("size", new THREE.BufferAttribute(nodeSize, 1));

      const lGeo = new THREE.BufferGeometry();
      lGeo.setAttribute("position", new THREE.BufferAttribute(linePos, 3));
      lGeo.setAttribute("color", new THREE.BufferAttribute(lineCol, 3));

      const pMat = new THREE.PointsMaterial({
        size: 0.14,
        map: tex,
        vertexColors: true,
        transparent: true,
        depthWrite: false,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending,
      });
      const lMat = new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0,
        depthWrite: false,
      });

      const points = new THREE.Points(pGeo, pMat);
      const lines = new THREE.LineSegments(lGeo, lMat);
      return { points, lines, nodePos, nodeCol, nodeSize, linePos, lineCol };
    }, [nodeCount, edgeCount, tex]);

  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      pointer.current.x = (e.clientX / window.innerWidth) * 2 - 1;
      pointer.current.y = (e.clientY / window.innerHeight) * 2 - 1;
    };
    window.addEventListener("pointermove", onMove, { passive: true });
    return () => window.removeEventListener("pointermove", onMove);
  }, []);

  const world = useMemo(() => new THREE.Vector3(), []);
  const cA = useMemo(() => new THREE.Color(), []);

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    const p = progressRef.current;
    const ph = phaseFromProgress(p);

    const pm = points.material as THREE.PointsMaterial;
    const lm = lines.material as THREE.LineBasicMaterial;

    // resolve node world positions for this frame
    const cur: THREE.Vector3[] = [];
    for (let i = 0; i < nodeCount; i++) {
      const b = model.base[i];
      const d = model.dirs[i];
      const breath = 0.05 * Math.sin(t * 0.6 + model.phase[i]);
      world.set(
        b.x + d.x * ph.fracture * 1.6 + breath,
        b.y + d.y * ph.fracture * 1.6 + Math.cos(t * 0.5 + model.phase[i]) * 0.05,
        b.z + d.z * ph.fracture * 1.6,
      );
      cur.push(world.clone());

      nodePos[i * 3] = world.x;
      nodePos[i * 3 + 1] = world.y;
      nodePos[i * 3 + 2] = world.z;

      // colour + size
      const moduleSlot = model.moduleIndex.indexOf(i);
      let brightness = i === 0 ? 0.9 : moduleSlot >= 0 ? 0.8 : 0.5;
      let size = i === 0 ? 1.5 : moduleSlot >= 0 ? 1.3 : 0.7;
      cA.copy(i === 0 || moduleSlot >= 0 ? COL_MODULE : COL_NODE);

      if (moduleSlot >= 0 && moduleSlot === ph.focus) {
        const f = ph.focusStrength;
        cA.lerp(COL_BRIGHT, f);
        brightness += f * 0.9;
        size += f * 1.1;
      }
      // gentle idle pulse on module nodes
      if (moduleSlot >= 0) brightness += 0.12 * (0.5 + 0.5 * Math.sin(t * 1.4 + moduleSlot));

      nodeCol[i * 3] = cA.r * brightness;
      nodeCol[i * 3 + 1] = cA.g * brightness;
      nodeCol[i * 3 + 2] = cA.b * brightness;
      nodeSize[i] = size * ph.opacity;
    }

    // lines follow node positions; colour encodes weave + focus + ledger pulse
    const ledger = smoothstep(0.72, 0.78, p) * (1 - smoothstep(0.86, 0.92, p));
    for (let e = 0; e < edgeCount; e++) {
      const [a, b] = model.edges[e];
      const va = cur[a];
      const vb = cur[b];
      const o = e * 6;
      linePos[o] = va.x;
      linePos[o + 1] = va.y;
      linePos[o + 2] = va.z;
      linePos[o + 3] = vb.x;
      linePos[o + 4] = vb.y;
      linePos[o + 5] = vb.z;

      // is this a spine edge (module triangle / hub)?
      const spine = e < 6;
      let bright = spine ? 0.88 : 0.42;

      // travelling pulse along threads during The Ledger
      if (ledger > 0) {
        const pulse = 0.5 + 0.5 * Math.sin(t * 2.2 - e * 0.9);
        bright += ledger * pulse * (spine ? 0.9 : 0.5);
      }
      // module focus lights that module's spokes
      if (ph.focus >= 0) {
        const mNode = model.moduleIndex[ph.focus];
        if (a === mNode || b === mNode) bright += ph.focusStrength * 0.7;
      }

      cA.copy(COL_THREAD).lerp(COL_BRIGHT, clamp01(bright - 0.6));
      const c = o;
      lineCol[c] = cA.r * bright;
      lineCol[c + 1] = cA.g * bright;
      lineCol[c + 2] = cA.b * bright;
      lineCol[c + 3] = cA.r * bright;
      lineCol[c + 4] = cA.g * bright;
      lineCol[c + 5] = cA.b * bright;
    }

    (points.geometry.attributes.position as THREE.BufferAttribute).needsUpdate = true;
    (points.geometry.attributes.color as THREE.BufferAttribute).needsUpdate = true;
    (points.geometry.attributes.size as THREE.BufferAttribute).needsUpdate = true;
    (lines.geometry.attributes.position as THREE.BufferAttribute).needsUpdate = true;
    (lines.geometry.attributes.color as THREE.BufferAttribute).needsUpdate = true;
    pm.opacity = ph.opacity;
    lm.opacity = ph.weave * ph.opacity;

    if (group.current) {
      // subtle scroll rotation + pointer parallax + footer contraction
      const targetRotY = p * 0.5 + pointer.current.x * 0.12;
      const targetRotX = -0.06 + pointer.current.y * 0.08;
      group.current.rotation.y += (targetRotY - group.current.rotation.y) * 0.04;
      group.current.rotation.x += (targetRotX - group.current.rotation.x) * 0.04;
      const s = 1 - 0.55 * ph.contract;
      group.current.scale.setScalar(s);
    }
  });

  // scale the whole field with viewport so it reads on wide and narrow screens
  const fit = Math.min(1.2, Math.max(0.72, size.width / 1400 + 0.55));

  return (
    <group ref={group} scale={fit}>
      <primitive object={lines} />
      <primitive object={points} />
    </group>
  );
}

export default function ThreadScene() {
  const progressRef = useRef(0);

  useEffect(() => {
    let raf = 0;
    const read = () => {
      const doc = document.documentElement;
      const max = doc.scrollHeight - window.innerHeight;
      progressRef.current = max > 0 ? clamp01(window.scrollY / max) : 0;
      raf = window.requestAnimationFrame(read);
    };
    raf = window.requestAnimationFrame(read);
    return () => window.cancelAnimationFrame(raf);
  }, []);

  return (
    <Canvas
      dpr={[1, 1.75]}
      gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
      camera={{ position: [0, 0, 7.2], fov: 42 }}
      style={{ width: "100%", height: "100%" }}
    >
      <Network progressRef={progressRef} />
    </Canvas>
  );
}
