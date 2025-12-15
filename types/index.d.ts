export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  kid?: string;
  use?: string;
  key_ops?: string[];
  [key: string]: unknown;
}

export interface JWTHeader {
  alg: "ES256";
  typ: "JWT";
  kid: string;
}

export interface JWTPayload {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
}

export class JWT {
  constructor(kid: string, iss: string, sub: string, exp: number);
  header: JWTHeader;
  payload: JWTPayload;

  /**
   * Sign the JWT with the given private JWK and return a compact JWS string.
   */
  static sign(privateJwk: JWK, jwt: JWT): Promise<string>;

  /**
   * Verify the JWT against the issuer's JWKS.
   * Resolves with the subject when valid; otherwise resolves to false.
   */
  static verify(token: string): Promise<string | false>;
}
