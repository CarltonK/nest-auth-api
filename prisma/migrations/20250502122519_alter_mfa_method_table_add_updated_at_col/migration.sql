/*
  Warnings:

  - Added the required column `updatedAt` to the `MfaMethod` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `MfaMethod` ADD COLUMN `updatedAt` DATETIME(3) NOT NULL;
