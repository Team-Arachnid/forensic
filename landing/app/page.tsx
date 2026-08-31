import { Hero } from "@/components/sections/hero";
import { Fracture } from "@/components/sections/fracture";
import { Thread } from "@/components/sections/thread";
import { Modules } from "@/components/sections/modules";
import { Ledger } from "@/components/sections/ledger";
import { Install } from "@/components/sections/install";

export default function Home() {
  return (
    <div id="top" className="relative z-10">
      <Hero />
      <Fracture />
      <Thread />
      <Modules />
      <Ledger />
      <Install />
    </div>
  );
}
