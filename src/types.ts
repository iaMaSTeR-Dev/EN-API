/**
 * Core type definitions for Eghtesad Novin Personal API Foundation.
 */

export interface SessionData {
  token: string;              // Bearer JWT / Yaghut token
  yaghootToken?: string;      // Core banking session token
  f5Cookie?: string;          // cookiesession1 persistence cookie
  deviceToken?: string;       // Pre-registered device token (mobileUserToken)
  createdAt: number;          // Epoch timestamp ms
  expiresAt: number;          // Estimated expiration timestamp ms
  lastActivityAt: number;     // Timestamp of last successful request
  cifOrUsername?: string;     // Non-sensitive user identifier
  generation?: number;        // Monotonic lifecycle generation counter
  savedCredentials?: {
    cifOrUsername: string;
    ciphertext: string;
    iv: string;
    tag: string;
  };
}

import type { AuthenticationState } from './auth/auth-state.ts';

export type AuthStatus = 
  | 'UNAUTHENTICATED' 
  | 'LOCAL_ACTIVE'
  | 'VERIFIED'
  | 'EXPIRED' 
  | 'REAUTHENTICATION_REQUIRED';

export interface SessionStatusResponse {
  status: AuthStatus;
  authenticationState?: AuthenticationState;
  isAuthenticated: boolean;
  hasLocalSession: boolean;
  isRemotelyVerified: boolean;
  expiresAt: string | null;
  lastActivityAt: string | null;
  lastVerifiedAt: string | null;
  idleTimeoutSeconds: number;
  hasPersistedSession?: boolean;
  hasSavedCredentials?: boolean;
  hasRegisteredDevice?: boolean;
  credentialsStorage?: 'MEMORY' | 'PERSISTED_ENCRYPTED' | 'NONE';
}

export type DeviceRegistrationOutcome =
  | { kind: 'otp_sent'; message: string; validationCode?: string }
  | { kind: 'captcha_required'; message: string }
  | { kind: 'rate_limited'; message: string; statusCode: number }
  | { kind: 'bank_error'; message: string; statusCode?: number; bankCode?: number }
  | { kind: 'network_error'; error: Error };

export type DeviceValidationOutcome =
  | { kind: 'success'; deviceToken: string; message: string }
  | { kind: 'invalid_code'; message: string; bankCode?: number }
  | { kind: 'bank_error'; message: string; statusCode?: number; bankCode?: number }
  | { kind: 'network_error'; error: Error };

export interface LoginCredentials {
  cifOrUsername: string;
  password: string;
  otp?: string;
  deviceToken?: string;
  saveCredentials?: boolean;
}

export interface LoginResult {
  success: boolean;
  status: AuthStatus;
  message: string;
  requiresOtp?: boolean;
  requiresCaptcha?: boolean;
  requiresDeviceToken?: boolean;
  bankCode?: number;
}

export interface HandoffTicket {
  handoffId: string;
  handoffSecret: string;
  expiresAt: number;
  loginUrl: string;
}

export interface BankAccount {
  depositNumber: string;
  uniqueId?: string;
  title: string;
  balance: number;
  availableBalance: number;
  currency: string;
  iban?: string;
  depositType?: string;
  depositOwnerType?: string;
  isVisible: boolean;
}

export interface CombinedBalance {
  currency: string;
  totalAvailableBalance: number;
  totalCurrentBalance: number;
  totalAvailableFormatted: string;
  totalCurrentFormatted: string;
  accountCount: number;
  accounts: {
    depositNumber: string;
    title: string;
    iban?: string;
    availableBalance: number;
    currentBalance: number;
  }[];
}

export interface UserProfile {
  cif?: string;
  username?: string;
  fullName: string;
  firstName?: string;
  lastName?: string;
  nationalCode?: string;
  mobileNumber?: string;
  lastLoginDate?: string;
  userType?: string;
}

export interface TransactionRecord {
  referenceId: string;
  trackingNumber?: string;
  transactionDate: string;
  transactionTime?: string;
  rawTimestamp?: number;
  jalaliDate?: string;
  jalaliTime?: string;
  gregorianDate?: string;
  gregorianTime?: string;
  isoTimestamp?: string;
  amount: number;
  amountFormatted?: string;
  balance?: number;
  balanceFormatted?: string;
  description: string;
  type?: string;
  isDebit: boolean;
}

export interface BankCard {
  cardUniqueId: string;
  maskedPan: string;
  title: string;
  expDate?: string;
  cardStatus?: string;
  linkedIban?: string;
  isDefault: boolean;
  bankName?: string;
  cardHolderName?: string;
}

export interface BankInfo {
  bankCode: string;
  bankName: string;
  persianName: string;
  bins: string[];
  logoUrl?: string;
}

export interface DestinationContact {
  type: 'deposit' | 'card' | 'iban';
  title: string;
  value: string;
  ownerName?: string;
  bankName?: string;
  id?: string;
}

export interface ScheduledTransfer {
  transferId: string;
  autoTransferType: 'NORMAL' | 'ACH';
  sourceDepositNumber: string;
  destinationNumber: string;
  destinationOwnerName?: string;
  amount: number;
  amountFormatted?: string;
  reasonTitle?: string;
  status?: string;
  termType?: string;
  termLength?: number;
  transactionCount?: number;
  startDate?: string;
  nextDate?: string;
}

export interface ChequeItem {
  sayadId?: string;
  chequeBookNumber?: string;
  serialNumber?: string;
  amount?: number;
  amountFormatted?: string;
  dueDate?: string;
  jalaliDueDate?: string;
  status?: string;
  statusTitle?: string;
  bankName?: string;
  issuerName?: string;
  receiverName?: string;
  isDigital?: boolean;
}

export interface LoanFacility {
  loanNumber: string;
  loanTitle?: string;
  totalAmount?: number;
  totalAmountFormatted?: string;
  remainAmount?: number;
  remainAmountFormatted?: string;
  installmentAmount?: number;
  installmentAmountFormatted?: string;
  paidCount?: number;
  unpaidCount?: number;
  totalCount?: number;
}

export interface LoanInstallment {
  installmentNumber: number;
  dueDate?: string;
  jalaliDueDate?: string;
  amount: number;
  amountFormatted?: string;
  isPaid: boolean;
  penaltyAmount?: number;
  paymentDate?: string;
}

export interface AdvertisementBanner {
  id: string;
  title: string;
  body?: string;
  type?: string;
  imageUrl?: string;
  linkUrl?: string;
}

export interface UtilityBill {
  id: string;
  billId: string;
  payId?: string;
  billType?: string;
  title?: string;
  amount?: number;
}

export interface IbanInquiryResult {
  iban: string;
  depositNumber?: string;
  ownerName: string;
  bankName?: string;
  status?: string;
}

export interface OwnerInquiryResult {
  identifierType: 'CARD' | 'IBAN' | 'DEPOSIT';
  identifier: string;
  ownerName: string;
  bankName?: string;
  depositNumber?: string;
  iban?: string;
}

export interface TopupItem {
  id?: string;
  phoneNumber: string;
  operator?: string;
  title?: string;
  date?: string;
}

export interface PackageItem {
  id?: string;
  phoneNumber: string;
  operator?: string;
  packageTitle?: string;
  title?: string;
  date?: string;
}

export interface BankApiResponse<T = unknown> {
  code: number;
  message: string;
  content: T;
}

export interface LocalApiErrorResponse {
  error: string;
  message: string;
  statusCode: number;
  details?: unknown;
}

export interface RequestRenewalMetadata {
  renewed: boolean;
  expiredLocally: boolean;
}

export interface RequestContext {
  readonly requestId: string;
  renewal?: RequestRenewalMetadata;
}

export interface ChequeBook {
  chequeBookNumber: string;
  depositNumber?: string;
  depositUniqueId?: string;
  count?: number;
  totalRecord?: number;
  isDigital?: boolean;
  status?: string;
  statusTitle?: string;
}

export interface ChequeSheet {
  sheetNumber: string;
  sayadId?: string;
  chequeBookNumber?: string;
  depositNumber?: string;
  state?: string;
  stateTitle?: string;
  amount?: number;
  amountFormatted?: string;
  dueDate?: string;
  jalaliDueDate?: string;
  isDigital?: boolean;
}

export interface ActiveSessionDevice {
  id?: string;
  sessionUid?: string;
  deviceName?: string;
  os?: string;
  browser?: string;
  ip?: string;
  lastActivity?: string;
  lastActivityParsed?: string;
  isCurrent?: boolean;
}

export interface EmailSettings {
  useEmailForTransfer?: boolean;
  useSmsForTransfer?: boolean;
  maskedEmail?: string;
  maskedMobile?: string;
}

export interface BillType {
  typeKey: string;
  typeName: string;
  code?: string;
  icon?: string;
}

export interface BillCompany {
  companyId: string;
  companyName: string;
  billType?: string;
}

export interface BillInquiryResult {
  billId: string;
  payId: string;
  amount: number;
  amountFormatted?: string;
  billType?: string;
  billTypeName?: string;
  title?: string;
  isPaid?: boolean;
  paymentDate?: string;
}

export interface UserMessage {
  id: string;
  title: string;
  body?: string;
  date?: string;
  isUnread?: boolean;
}

export interface MobileOperator {
  operatorId: string;
  name: string;
  title: string;
  code?: string;
}

export interface TopUpAmount {
  amount: number;
  amountFormatted: string;
  operator?: string;
}

export interface PackageOption {
  id?: string;
  title: string;
  price: number;
  priceFormatted: string;
  operator?: string;
  duration?: string;
  dataLimit?: string;
  isAvailable?: boolean;
}

export interface CardBalance {
  cardUniqueId: string;
  maskedPan: string;
  balance: number;
  availableBalance: number;
  currency: string;
  balanceFormatted: string;
  availableBalanceFormatted: string;
}

export interface CardStatementItem {
  referenceId: string;
  date: string;
  jalaliDate?: string;
  amount: number;
  amountFormatted: string;
  isDebit: boolean;
  description: string;
}

export interface InterBankRules {
  payaCeiling?: number;
  satnaFloor?: number;
  satnaCeiling?: number;
  cardTransferCeiling?: number;
  rules?: Array<{ ruleKey: string; ruleValue: string; description?: string }>;
}

export interface TransactionSearchResult {
  transactionId?: string;
  resourceType?: string;
  resourceUniqueId?: string;
  date?: string;
  jalaliDate?: string;
  amount: number;
  amountFormatted: string;
  isDebit: boolean;
  description: string;
}



