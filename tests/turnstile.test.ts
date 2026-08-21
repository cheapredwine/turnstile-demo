// Turnstile Tests with remoteip_leniency parameter

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { handleTurnstileVerification, verifyTurnstileToken } from '../src/index';

describe('Turnstile Verification', () => {
  let mockEnv: any;
  let mockFetch: any;

  beforeEach(() => {
    mockEnv = {
      TURNSTILE_SECRET: 'test-secret-key',
      TURNSTILE_SITE_KEY: 'test-site-key'
    };
    mockFetch = vi.fn();
    global.fetch = mockFetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('verifyTurnstileToken', () => {
    it('should include remoteip_leniency parameter in verification request', async () => {
      const mockResponse = {
        success: true,
        "error-codes": [],
        "remoteip_leniency": "strict"
      };

      mockFetch.mockResolvedValueOnce({
        json: async () => mockResponse
      } as Response);

      const token = 'test-token-123';
      const clientIp = '192.168.1.1';

      const result = await verifyTurnstileToken(token, clientIp, mockEnv);

      expect(mockFetch).toHaveBeenCalledWith('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        body: expect.any(FormData),
        method: 'POST'
      });

      const formData = mockFetch.mock.calls[0][1].body as FormData;
      expect(formData.get('secret')).toBe(mockEnv.TURNSTILE_SECRET);
      expect(formData.get('response')).toBe(token);
      expect(formData.get('remoteip')).toBe(clientIp);
      expect(formData.get('remoteip_leniency')).toBe('strict');
      expect(result).toEqual(mockResponse);
    });

    it('should handle successful verification response', async () => {
      const mockResponse = {
        success: true,
        "error-codes": [],
        challenge_ts: '2024-01-01T00:00:00Z',
        hostname: 'example.com',
        "remoteip_leniency": "strict"
      };

      mockFetch.mockResolvedValueOnce({
        json: async () => mockResponse
      } as Response);

      const result = await verifyTurnstileToken('test-token', '192.168.1.1', mockEnv);

      expect(result.success).toBe(true);
      expect(result["error-codes"]).toEqual([]);
      expect(result.hostname).toBe('example.com');
      expect(result["remoteip_leniency"]).toBe('strict');
    });

    it('should handle failed verification response', async () => {
      const mockResponse = {
        success: false,
        "error-codes": ['invalid-input-response'],
        "remoteip_leniency": "strict"
      };

      mockFetch.mockResolvedValueOnce({
        json: async () => mockResponse
      } as Response);

      const result = await verifyTurnstileToken('invalid-token', '192.168.1.1', mockEnv);

      expect(result.success).toBe(false);
      expect(result["error-codes"]).toEqual(['invalid-input-response']);
      expect(result["remoteip_leniency"]).toBe('strict');
    });

    it('should handle missing client IP gracefully', async () => {
      const mockResponse = {
        success: true,
        "error-codes": [],
        "remoteip_leniency": "strict"
      };

      mockFetch.mockResolvedValueOnce({
        json: async () => mockResponse
      } as Response);

      const result = await verifyTurnstileToken('test-token', '0.0.0.0', mockEnv);

      expect(result.success).toBe(true);
      expect(result["remoteip_leniency"]).toBe('strict');
    });
  });

  describe('handleTurnstileVerification', () => {
    it('should return 400 when no token is provided', async () => {
      const request = new Request('http://localhost/form', {
        method: 'POST',
        body: new FormData()
      });

      const response = await handleTurnstileVerification(request, mockEnv);

      expect(response.status).toBe(400);
      expect(await response.text()).toContain('No Turnstile token provided');
    });

    it('should return 401 when token verification fails', async () => {
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'invalid-token');

      const request = new Request('http://localhost/form', {
        method: 'POST',
        body: formData
      });

      // First call fails with invalid-input-response
      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: false,
          "error-codes": ['invalid-input-response'],
          "remoteip_leniency": "strict"
        })
      } as Response);

      // Second call (double-call pattern with 'off') also fails - token genuinely invalid
      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: false,
          "error-codes": ['invalid-input-response']
        })
      } as Response);

      const response = await handleTurnstileVerification(request, mockEnv);

      expect(response.status).toBe(401);
      expect(await response.text()).toContain('Verification Failed');
    });

    it('should return success message when token is valid', async () => {
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'valid-token');

      const request = new Request('http://localhost/form', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': '192.168.1.1' },
        body: formData
      });

      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: true,
          "error-codes": [],
          "remoteip_leniency": "strict"
        })
      } as Response);

      const response = await handleTurnstileVerification(request, mockEnv);

      expect(response.status).toBe(200);
      const text = await response.text();
      expect(text).toContain('Verification Successful');
      expect(text).toContain('192.168.1.1');
    });

    it('should include remoteip_leniency in success response', async () => {
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'valid-token');

      const request = new Request('http://localhost/form', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': '192.168.1.1' },
        body: formData
      });

      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: true,
          "error-codes": [],
          "remoteip_leniency": "strict"
        })
      } as Response);

      const response = await handleTurnstileVerification(request, mockEnv);

      const text = await response.text();
      // HTML response now contains JSON in <pre> tag - just check it mentions the mode
      expect(text).toContain('strict');
      expect(text).toContain('Verification Successful');
    });
  });

  describe('remoteip_leniency Parameter', () => {
    const testCases = [
      { value: 'strict', description: 'strict mode' },
      { value: 'relaxed', description: 'relaxed mode' },
      { value: 'off', description: 'off mode' }
    ];

    testCases.forEach(({ value, description }) => {
      it(`should use "${value}" mode for remoteip_leniency - ${description}`, async () => {
        const formData = new FormData();
        formData.append('cf-turnstile-response', 'test-token');

        const request = new Request('http://localhost/form', {
          method: 'POST',
          headers: { 'CF-Connecting-IP': '192.168.1.1' },
          body: formData
        });

        mockFetch.mockResolvedValueOnce({
          json: async () => ({
            success: true,
            "error-codes": [],
            "remoteip_leniency": value
          })
        } as Response);

        await verifyTurnstileToken('test-token', '192.168.1.1', mockEnv, value as any);

        const formDataArg = mockFetch.mock.calls[0][1].body as FormData;
        expect(formDataArg.get('remoteip_leniency')).toBe(value);
      });

      it(`should maintain remoteip_leniency "${value}" in response - ${description}`, async () => {
        const formData = new FormData();
        formData.append('cf-turnstile-response', 'test-token');

        const request = new Request('http://localhost/form', {
          method: 'POST',
          headers: { 'CF-Connecting-IP': '192.168.1.1' },
          body: formData
        });

        mockFetch.mockResolvedValueOnce({
          json: async () => ({
            success: true,
            "error-codes": [],
            "remoteip_leniency": value
          })
        } as Response);

        const response = await handleTurnstileVerification(request, mockEnv);
        const text = await response.text();
        // HTML response contains the mode value somewhere
        expect(text).toContain(value);
        expect(text).toContain('Verification Successful');
      });
    });

    it('should pass all three values correctly through the verification flow', async () => {
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'test-token');

      const request = new Request('http://localhost/form', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': '192.168.1.1' },
        body: formData
      });

      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: true,
          "error-codes": [],
          "remoteip_leniency": "strict"
        })
      } as Response);

      await verifyTurnstileToken('test-token', '192.168.1.1', mockEnv, 'strict');

      const formDataArg = mockFetch.mock.calls[0][1].body as FormData;
      expect(formDataArg.get('remoteip_leniency')).toBe('strict');
    });
  });

  describe('remoteip_leniency Edge Cases', () => {
    it('should handle "strict" mode correctly', async () => {
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'test-token');

      const request = new Request('http://localhost/form', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': '192.168.1.1' },
        body: formData
      });

      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: true,
          "error-codes": [],
          "remoteip_leniency": "strict"
        })
      } as Response);

      await verifyTurnstileToken('test-token', '192.168.1.1', mockEnv, 'strict');

      const formDataArg = mockFetch.mock.calls[0][1].body as FormData;
      expect(formDataArg.get('remoteip_leniency')).toBe('strict');
    });

    it('should handle "relaxed" mode correctly', async () => {
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'test-token');

      const request = new Request('http://localhost/form', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': '192.168.1.1' },
        body: formData
      });

      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: true,
          "error-codes": [],
          "remoteip_leniency": "relaxed"
        })
      } as Response);

      await verifyTurnstileToken('test-token', '192.168.1.1', mockEnv, 'relaxed');

      const formDataArg = mockFetch.mock.calls[0][1].body as FormData;
      expect(formDataArg.get('remoteip_leniency')).toBe('relaxed');
    });

    it('should handle "off" mode correctly', async () => {
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'test-token');

      const request = new Request('http://localhost/form', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': '192.168.1.1' },
        body: formData
      });

      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: true,
          "error-codes": [],
          "remoteip_leniency": "off"
        })
      } as Response);

      await verifyTurnstileToken('test-token', '192.168.1.1', mockEnv, 'off');

      const formDataArg = mockFetch.mock.calls[0][1].body as FormData;
      expect(formDataArg.get('remoteip_leniency')).toBe('off');
    });

    it('should default to "strict" when no leniency mode is specified', async () => {
      const formData = new FormData();
      formData.append('cf-turnstile-response', 'test-token');

      const request = new Request('http://localhost/form', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': '192.168.1.1' },
        body: formData
      });

      mockFetch.mockResolvedValueOnce({
        json: async () => ({
          success: true,
          "error-codes": [],
          "remoteip_leniency": "strict"
        })
      } as Response);

      await verifyTurnstileToken('test-token', '192.168.1.1', mockEnv);

      const formDataArg = mockFetch.mock.calls[0][1].body as FormData;
      expect(formDataArg.get('remoteip_leniency')).toBe('strict');
    });
  });
});