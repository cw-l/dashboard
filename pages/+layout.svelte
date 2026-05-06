<script>
	import '@evidence-dev/tailwind/fonts.css';
	import '../app.css';
	import { EvidenceDefaultLayout } from '@evidence-dev/core-components';
	import { LastRefreshed } from '@evidence-dev/core-components';
	export let data;
</script>

<EvidenceDefaultLayout {data} logo="/logo.png" neverShowQueries={true} builtWithEvidence={false}>
	<slot slot="content" />
</EvidenceDefaultLayout>

<footer style="display: grid; place-items: center; row-gap: 8px; font-size: 0.75rem; opacity: 0.8; margin-top: 3rem; padding-bottom: 2rem; color: currentColor;">
    <div style="height: 1rem; display: flex; align-items: center;">
        <LastRefreshed />
    </div>
    <div style="display: flex; gap: 12px; align-items: center;">
        <a href="/credits" style="text-decoration: none; color: inherit;">Credits</a>
        <span>|</span>
        <a href="/disclaimer" style="text-decoration: none; color: inherit;">Disclaimer</a>
        <span>|</span>
        <a href="/privacy" style="text-decoration: none; color: inherit;">Privacy</a>
    </div>
    <div>
        © {new Date().getFullYear()} BCF Security. All rights reserved.
    </div>
</footer>

<style>
    /* Ensures all internal components inherit the same color and size */
    footer :global(p), 
    footer :global(div), 
    footer :global(span) {
        margin: 0 !important;
        padding: 0 !important;
        font-size: inherit !important;
        color: inherit !important;
        line-height: 1 !important;
    }

    footer a:hover {
        text-decoration: underline !important;
    }
</style>