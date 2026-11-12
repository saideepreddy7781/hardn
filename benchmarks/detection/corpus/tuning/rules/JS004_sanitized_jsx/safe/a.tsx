const A = () => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(x) }} />;
