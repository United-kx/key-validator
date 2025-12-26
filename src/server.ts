import { config as loadEnv } from 'dotenv';
import cors from 'cors';
import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { createClient } from '@supabase/supabase-js';
import crypto from 'node:crypto';
import { z } from 'zod';

loadEnv();

const app = express();

const PORT = Number(process.env.PORT ?? 4000);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables');
}

if (!ADMIN_TOKEN) {
  throw new Error('Missing ADMIN_TOKEN environment variable');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  },
});

app.use(helmet());
const corsOrigins = process.env.CORS_ORIGIN?.split(',').map((origin) => origin.trim()).filter(Boolean);

app.use(
  cors({
    origin: corsOrigins && corsOrigins.length > 0 ? corsOrigins : '*',
  })
);
app.use(express.json());

interface ApiError extends Error {
  status?: number;
}

const requestSchema = z.object({
  pin: z
    .string()
    .min(4)
    .max(64)
    .transform((value) => value.trim().toUpperCase()),
});

const keyRecordSchema = z.object({
  id: z.string(),
  pin: z.string(),
  user_id: z.string().nullable(),
  created_at: z.string(),
  expires_at: z.string(),
  used_at: z.string().nullable(),
});

const createPinResponseSchema = z.object({
  ok: z.literal(true),
  pin: z.string(),
  expiresAt: z.string(),
  userId: z.string().nullable(),
});

function isAuthorized(req: Request) {
  const authHeader = req.header('authorization');
  if (!authHeader) {
    return false;
  }

  const [scheme, token] = authHeader.split(' ');
  return scheme?.toLowerCase() === 'bearer' && token === ADMIN_TOKEN;
}

function generatePin(length = 12) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(length);
  let pin = '';
  for (let i = 0; i < length; i += 1) {
    pin += alphabet[bytes[i] % alphabet.length];
  }
  return pin;
}

function computeExpiry(minutes = 30) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

async function fetchKey(pin: string) {
  const { data, error } = await supabase
    .from('pins')
    .select('*')
    .eq('pin', pin)
    .single();

  if (error) {
    const apiError: ApiError = new Error('Failed to query Supabase');
    apiError.status = 500;
    throw apiError;
  }

  if (!data) {
    const apiError: ApiError = new Error('PIN not found');
    apiError.status = 404;
    throw apiError;
  }

  return keyRecordSchema.parse(data);
}

function validateExpiry(expiresAt: string) {
  const expiry = new Date(expiresAt);
  if (Number.isNaN(expiry.getTime())) {
    const apiError: ApiError = new Error('Invalid expiry timestamp');
    apiError.status = 500;
    throw apiError;
  }

  if (expiry < new Date()) {
    const apiError: ApiError = new Error('PIN expired');
    apiError.status = 410;
    throw apiError;
  }
}

async function ensureUniquePin(pin: string) {
  const { data } = await supabase
    .from('pins')
    .select('pin')
    .eq('pin', pin)
    .maybeSingle();

  if (!data) {
    return pin;
  }

  return ensureUniquePin(generatePin(pin.length));
}

async function deleteExistingPinsForUser(userId: string) {
  const { error } = await supabase
    .from('pins')
    .delete()
    .eq('user_id', userId);

  if (error) {
    const apiError: ApiError = new Error('Failed to clean existing keys for user');
    apiError.status = 500;
    throw apiError;
  }
}

async function storePin(pin: string, userId: string | null, expiresAt: string) {
  const { data, error } = await supabase
    .from('pins')
    .insert({ pin, user_id: userId, expires_at: expiresAt })
    .select('*')
    .single();

  if (error) {
    const apiError: ApiError = new Error('Failed to persist PIN');
    apiError.status = 500;
    throw apiError;
  }

  return keyRecordSchema.parse(data);
}

async function markPinUsed(id: string) {
  const now = new Date().toISOString();
  const { data, error } = await supabase
    .from('pins')
    .update({ used_at: now })
    .eq('id', id)
    .is('used_at', null)
    .select('*')
    .single();

  if (error) {
    const apiError: ApiError = new Error('Failed to update PIN usage');
    apiError.status = 500;
    throw apiError;
  }

  return keyRecordSchema.parse(data);
}

app.get('/health', (_req: Request, res: Response) => {
  res.json({ ok: true, service: 'key-validator', time: new Date().toISOString() });
});

app.post('/api/pins', async (req: Request, res: Response, next: NextFunction) => {
  if (!isAuthorized(req)) {
    res.status(401).json({ ok: false, message: 'Unauthorized' });
    return;
  }

  const bodySchema = z.object({
    userId: z.string().min(1).max(64).optional(),
    expiresInMinutes: z.number().int().positive().max(240).optional(),
  });

  try {
    const { userId = null, expiresInMinutes = 30 } = bodySchema.parse(req.body ?? {});

    if (userId) {
      await deleteExistingPinsForUser(userId);
    }

    const uniquePin = await ensureUniquePin(generatePin());
    const expiresAt = computeExpiry(expiresInMinutes);
    const savedRecord = await storePin(uniquePin, userId, expiresAt);

    const responsePayload = createPinResponseSchema.parse({
      ok: true,
      pin: savedRecord.pin,
      expiresAt: savedRecord.expires_at,
      userId: savedRecord.user_id,
    });

    res.status(201).json(responsePayload);
  } catch (error) {
    next(error);
  }
});

app.post('/api/pins/verify', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { pin } = requestSchema.parse(req.body);
    const record = await fetchKey(pin);
    validateExpiry(record.expires_at);

    if (record.used_at) {
      const apiError: ApiError = new Error('PIN already used');
      apiError.status = 410;
      throw apiError;
    }

    const updatedRecord = await markPinUsed(record.id);

    res.json({
      ok: true,
      pin: updatedRecord.pin,
      userId: updatedRecord.user_id,
      createdAt: updatedRecord.created_at,
      expiresAt: updatedRecord.expires_at,
      usedAt: updatedRecord.used_at,
    });
  } catch (error) {
    next(error);
  }
});

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  let status = 500;
  let message = 'Internal Server Error';

  if (error instanceof z.ZodError) {
    status = 400;
    message = error.issues.map((issue) => issue.message).join(', ');
  } else if (error instanceof Error) {
    status = (error as ApiError).status ?? status;
    message = error.message;
  }

  res.status(status).json({ ok: false, message });
});

app.listen(PORT, () => {
  console.log(`[key-validator] listening on port ${PORT}`);
});
