"use client";

import { cva, type VariantProps } from "class-variance-authority";
import { twMerge } from "tailwind-merge";

const badgeVariants = cva(
  "inline-flex items-center rounded-sm px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
  {
    variants: {
      severity: {
        critical:
          "bg-cyber-red/20 text-cyber-red border border-cyber-red/40",
        high: "bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40",
        medium:
          "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40",
        low: "bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40",
      },
    },
    defaultVariants: {
      severity: "low",
    },
  },
);

interface BadgeProps extends VariantProps<typeof badgeVariants> {
  children: React.ReactNode;
  className?: string;
}

export default function Badge({ severity, children, className }: BadgeProps) {
  return (
    <span className={twMerge(badgeVariants({ severity }), className)}>
      {children}
    </span>
  );
}
