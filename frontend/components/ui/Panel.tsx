"use client";

import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

interface PanelProps {
  title?: string;
  children: React.ReactNode;
  className?: string;
  noPad?: boolean;
}

export default function Panel({
  title,
  children,
  className,
  noPad = false,
}: PanelProps) {
  return (
    <div
      className={twMerge(
        clsx(
          "panel-glow hud-bracket rounded-sm overflow-hidden",
          !noPad && "p-4",
          className,
        ),
      )}
    >
      {title && (
        <div className="flex items-center gap-2 mb-3 pb-2 border-b border-navy-600/50">
          <div className="w-2 h-2 bg-cyber-cyan rounded-full" />
          <h2 className="text-xs uppercase tracking-[0.2em] text-cyber-cyan font-semibold">
            {title}
          </h2>
          <div className="flex-1 h-px bg-gradient-to-r from-cyber-cyan/30 to-transparent" />
        </div>
      )}
      {children}
    </div>
  );
}
