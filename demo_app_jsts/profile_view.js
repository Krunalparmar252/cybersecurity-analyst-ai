import DOMPurify from 'dompurify';

// SEEDED BUG: unsanitised HTML from props (XSS-001)
export const Bio = ({ html }) => (
    <div dangerouslySetInnerHTML={{ __html: html }} />  // GT:XSS-001
);

// SAFE: sanitised, must NOT fire
export const BioSafe = ({ html }) => (
    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />  // SAFE
);

// SAFE: constant literal, must NOT fire
export const Banner = () => (
    <div dangerouslySetInnerHTML={{ __html: "<b>Welcome</b>" }} />  // SAFE
);
