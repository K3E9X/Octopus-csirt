import Cases from "@/components/Cases";
export const dynamic = "force-dynamic";
export default function Page({ searchParams }: { searchParams: { id?: string } }) {
  return <Cases initialId={searchParams.id} />;
}
