export function requireEnv(name) {
    const value = process.env[name];
    if (value === undefined) {
        throw new Error(`Missing environment variable \`${name}\``);
    }
    return value;
}
