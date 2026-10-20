import { prisma } from '../prisma';

export interface ShredCandidate {
  id: string;
  title: string;
  ownerId: string;
  storedFilenames: string[];
}

export async function findShredCandidates(olderThanDays = 30): Promise<ShredCandidate[]> {
  const threshold = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);

  const docs = await prisma.document.findMany({
    where: {
      isDeleted: true,
      deletedAt: { lte: threshold }
    },
    include: {
      versions: true
    }
  });

  return docs.map((doc) => {
    const filenames = new Set<string>();
    if (doc.storedFilename) filenames.add(doc.storedFilename);
    for (const v of doc.versions) {
      if (v.storedFilename) filenames.add(v.storedFilename);
    }

    return {
      id: doc.id,
      title: doc.title,
      ownerId: doc.ownerId,
      storedFilenames: Array.from(filenames)
    };
  });
}

export async function findDocumentForImmediateShred(documentId: string): Promise<ShredCandidate | null> {
  const doc = await prisma.document.findUnique({
    where: { id: documentId },
    include: { versions: true }
  });

  if (!doc) return null;

  const filenames = new Set<string>();
  if (doc.storedFilename) filenames.add(doc.storedFilename);
  for (const v of doc.versions) {
    if (v.storedFilename) filenames.add(v.storedFilename);
  }

  return {
    id: doc.id,
    title: doc.title,
    ownerId: doc.ownerId,
    storedFilenames: Array.from(filenames)
  };
}

export async function deleteShreddedDocumentRecords(documentId: string): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.documentPermission.deleteMany({ where: { documentId } });
    await tx.documentVersion.deleteMany({ where: { documentId } });
    await tx.document.delete({ where: { id: documentId } });
  });
}
