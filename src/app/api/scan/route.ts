import { NextRequest, NextResponse } from "next/server";
import { analyzeUrl } from "@/services/analyzer";

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const targetUrl = searchParams.get("url") || "";

  const result = analyzeUrl(targetUrl);
  return NextResponse.json(result, {
    status: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "public, s-maxage=60, stale-while-revalidate=120",
    },
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const targetUrl = typeof body?.url === "string" ? body.url : "";

    const result = analyzeUrl(targetUrl);
    return NextResponse.json(result, {
      status: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON payload provided." },
      { status: 400 }
    );
  }
}
