#!/bin/bash

# Turnstile Demo Deployment Script
# This script deploys the worker to Cloudflare Workers

set -e

echo "🚀 Deploying Turnstile Demo to Cloudflare Workers..."
echo ""

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    echo "❌ Wrangler is not installed. Please install it first:"
    echo "   npm install -g wrangler"
    exit 1
fi

# Check if token exists
if [ ! -f ~/.cf-turnstile-token ]; then
    echo "❌ Cloudflare API token not found. Please provide it:"
    echo "   printf 'Cloudflare API token: '; read token; echo; printf '%s' "$token" > ~/.cf-turnstile-token; unset token"
    exit 1
fi

# Set up environment
export WRANGLER_TELEMETRY_DISABLED=1
export CLOUDFLARE_API_TOKEN=$(cat ~/.cf-turnstile-token)
unset WRANGLER_TELEMETRY_DISABLED
unset CLOUDFLARE_API_TOKEN

# Deploy the worker
echo "📦 Deploying worker..."
wrangler deploy --name turnstile-demo

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🌐 Your worker is now available at:"
echo "   https://turnstile-demo.jsherron.workers.dev"
echo ""
echo "📝 To add a custom domain (jsherron.com):"
echo "   1. Go to Cloudflare Dashboard → Workers & Pages → turnstile-demo"
echo "   2. Click Triggers → Custom Domains"
echo "   3. Add domain: jsherron.com"
echo ""
echo "🛣️  IMPORTANT: After adding the custom domain, enable the route:"
echo "   1. Go to Cloudflare Dashboard → Triggers → Routes"
echo "   2. Create route: turnstile-demo.jsherron-test-account.workers.dev"
echo "   3. This maps your custom domain to the worker"
echo ""
echo "🧪 Test the integration:"
echo "   curl https://turnstile-demo.jsherron.workers.dev/form"