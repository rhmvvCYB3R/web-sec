/*
WebSec L6 — Next.js-compatible React single-file app
File: components/WebSecApp.jsx

Исправления и Дополнения:
1. Корректировка стилей Tailwind для темной темы: 'text-black dark:text-black' изменено на 'text-black dark:text-white' в корневом контейнере и его дочерних элементах для обеспечения читаемости в темном режиме.
2. Инициализация состояния заметок: Корректная загрузка 'websec_notes' из localStorage при первом рендере.
3. Улучшение генерации нового вопроса викторины (generateNewQuizQuestion):
   - Разделена на две функции: `generateCoreQuizQuestion` (для основных тем) и `generateAppQuizQuestion` (для вопросов о применениях).
   - Основная логика викторины теперь **случайно выбирает** вопрос либо из **основных тем**, либо из **вопросов о применениях** (`QUIZ_APPLICATIONS`), если они доступны для выбранного `topicId`.
   - Новая функция `generateNewQuizQuestion` теперь выбирает вопрос из обоих источников.
4. НОВЫЕ ДАННЫЕ: Добавлен массив QUIZ_APPLICATIONS с вопросами по применению технологий в различных областях (Information Security, Financial Services и т.д.). (Уже было в вашем коде, но я обеспечил его использование).
5. ИСПРАВЛЕНО: Ошибки TypeScript "noImplicitAny" в функциях genDistractors и generateCoreQuizQuestion.
*/
"use client";
import React, { useEffect, useMemo, useState, useCallback } from 'react'

// --- Data: core topics and research reports ---
const CORE_TOPICS = [
  {
    id: 'session_attack',
    title: 'Session attack',
    prompts: [
      'What is the attack?',
      'How is it done?',
      'How to defend against it? (as an Application Security Engineer)'
    ],
    summary:
      'An attack that steals, fixes, predicts, or replays a user\'s session identifier (cookie/token) to impersonate that user (session hijacking, fixation, replay, predictable IDs, token theft)'
  },
  {
    id: 'hashing',
    title: 'Hashing',
    summary:
      'Hashing converts data into a fixed-length value (hash). It is one-way and used to check data integrity. Small input changes cause large hash changes. Used to store passwords (hashed), verify files, and as a core primitive in blockchain.'
  },
  {
    id: 'encryption',
    title: 'Encryption',
    summary:
      'Encryption turns plaintext into ciphertext using keys. Types: symmetric (AES) and asymmetric (RSA). Ensures confidentiality in storage and transit (e.g., HTTPS).'
  },
  {
    id: 'digital_signature',
    title: 'Digital Signature',
    summary:
      'Digital signatures prove authenticity and integrity by signing data with a private key and verifying with a public key (e.g., ECDSA).'
  }
]

const RESEARCH_REPORTS = [
  {
    slug: 'brute-force',
    title: 'Brute Force Attack',
    what: 'A brute force attack systematically tries many possible keys, passwords, or inputs until it finds the correct one. It exploits weak or short secrets and predictable rate-limiting.',
    how: 'Automated tools iterate over candidate inputs (dictionary, combinatorics). Attackers may use GPUs, botnets, or cloud resources to increase throughput. Often combined with credential stuffing using leaked combos.',
    defend:
      'As an AppSec Engineer: enforce strong password policies (length + entropy), apply account lockouts/rate-limiting, use multi-factor authentication (MFA), implement progressive delays and IP reputation checks, and monitor for anomalous login patterns. Hash and salt passwords with slow KDFs (bcrypt, Argon2).'
  },
  {
    slug: 'rainbow-tables',
    title: 'Rainbow Tables Attack',
    what: 'Precomputed tables mapping hashes to plaintexts to reverse common hashing functions quickly for unsalted hashes.',
    how: 'Attacker builds or acquires tables for target hash function (e.g., MD5, SHA-1) and looks up user hashes to recover passwords rapidly. Works only when salts are absent or weak.',
    defend:
      'Use unique, per-password salts and modern slow hashing algorithms (bcrypt, Argon2). Increase iteration counts, use pepper if needed, and migrate away from fast hashes (MD5, SHA-1) to slow KDFs. Store metadata (salt, version) with hashed record.'
  },
  {
    slug: 'collision',
    title: 'Collision Attack',
    what: 'An attack that finds two distinct inputs producing the same hash (collision), undermining integrity properties of the hash function.',
    how: 'Using mathematical weaknesses in hash functions (e.g., MD5/SHA-1 collision techniques) attackers craft different payloads with identical hashes to bypass integrity checks or digital signature assumptions.',
    defend:
      'Avoid deprecated hash functions (MD5, SHA-1). Use collision-resistant functions (SHA-256+), add signatures when integrity matters, and adopt library updates. For file integrity, include HMAC or digital signatures rather than raw hashes.'
  },
  {
    slug: 'ransomware',
    title: 'Ransomware Attack',
    what: 'Malware that encrypts an organization\'s files and demands payment (ransom) for the decryption key, often combined with data exfiltration.',
    how: 'Delivered via phishing, insecure RDP, software vulnerabilities, or supply-chain compromises. Once inside, attackers escalate privileges, spread laterally, exfiltrate data, and deploy encryption payloads with cleanup/anti-forensics steps.',
    defend:
      'Apply defense-in-depth: endpoint protection, timely patching, least privilege, network segmentation, MFA for all remote access, secure backups with air-gapped copies, data loss prevention (DLP), and incident response playbooks. Train staff on phishing and run red-team exercises.'
  }
]

// --- New Data: Application-specific questions ---
// Data structure: { area: string, topic: string, question: string, answer: string }
const QUIZ_APPLICATIONS = [
  // Hashing Applications
  { area: 'Information Security', topic: 'Hashing', question: 'What is the primary function of hashing for protecting passwords in systems?', answer: 'Systems store only hashed passwords (not the real ones) to prevent theft and direct use of credentials.' },
  { area: 'Financial Services', topic: 'Hashing', question: 'How does hashing help secure PINs and transactions in Financial Services?', answer: 'It is used to secure PINs and checks that transactions are not changed (ensuring integrity).' },
  { area: 'Healthcare', topic: 'Hashing', question: 'In Healthcare, how does hashing confirm that medical records are not modified?', answer: 'It helps confirm that medical records are not modified by checking data integrity.' },
  { area: 'E-commerce', topic: 'Hashing', question: 'What practical e-commerce task uses hashing related to downloaded files?', answer: 'It verifies downloaded files to ensure they haven\'t been tampered with during transfer.' },
  { area: 'Government and Defense', topic: 'Hashing', question: 'For what purpose is hashing used in Government and Defense regarding documents?', answer: 'It ensures documents are authentic (provenance and integrity).' },
  { area: 'Cloud Computing', topic: 'Hashing', question: 'What is the main application of hashing in Cloud Computing?', answer: 'It is used for data integrity checks to ensure files stored in the cloud are unchanged.' },
  { area: 'Blockchain Technology', topic: 'Hashing', question: 'How does hashing prevent tampering in Blockchain Technology?', answer: 'Each block has the hash of the previous one, creating a chain that prevents tampering.' },

  // Encryption Applications
  { area: 'Information Security', topic: 'Encryption', question: 'What general goal does encryption achieve for data in storage and transit? (Give a website example)', answer: 'It protects data in storage and transmission; for example, HTTPS uses encryption to secure websites.' },
  { area: 'Financial Services', topic: 'Encryption', question: 'What specifically does encryption protect in financial services, besides transactions?', answer: 'It protects transactions and customer data.' },
  { area: 'Healthcare', topic: 'Encryption', question: 'What law requires encrypting patient information in the Healthcare sector?', answer: 'Laws like HIPAA require encrypting patient information.' },
  { area: 'E-commerce', topic: 'Encryption', question: 'What crucial information in e-commerce is secured using encryption?', answer: 'It secures payment information.' },
  { area: 'Government and Defense', topic: 'Encryption', question: 'What category of data does encryption protect in the Government and Defense sectors?', answer: 'It protects confidential data.' },
  { area: 'Cloud Computing', topic: 'Encryption', question: 'How do cloud companies like AWS or Azure use encryption to secure stored files?', answer: 'They use encryption to secure stored files.' },
  { area: 'Blockchain Technology', topic: 'Encryption', question: 'What critical user property is protected by encryption in the blockchain (e.g., Bitcoin)?', answer: 'It secures private keys and wallets.' },

  // Digital Signature Applications
  { area: 'Information Security', topic: 'Digital Signature', question: 'What double assurance does a digital signature provide for files or messages?', answer: 'It ensures that files or messages come from a trusted source (authenticity) and have not been changed (integrity).' },
  { area: 'Financial Services', topic: 'Digital Signature', question: 'Provide examples of documents or processes in Financial Services that use digital signatures (e.g., DocuSign).', answer: 'It is used for signing contracts and online transactions.' },
  { area: 'Healthcare', topic: 'Digital Signature', question: 'What is the main function of a digital signature in Healthcare related to reports and prescriptions?', answer: 'It authenticates reports and prescriptions.' },
  { area: 'E-commerce', topic: 'Digital Signature', question: 'What does a digital signature confirm in e-commerce related to payments?', answer: 'It confirms payment authenticity.' },
  { area: 'Government and Defense', topic: 'Digital Signature', question: 'What critical information related to identification do digital signatures protect in Government and Defense?', answer: 'It secures IDs and official documents.' },
  { area: 'Cloud Computing', topic: 'Digital Signature', question: 'What is a digital signature used for in Cloud Computing related to software or APIs?', answer: 'It verifies software or API integrity.' },
  { area: 'Blockchain Technology', topic: 'Digital Signature', question: 'What specific process in the blockchain (e.g., Bitcoin) requires digital signatures to verify ownership?', answer: 'Every transaction is signed digitally (e.g., Bitcoin uses ECDSA to verify ownership).' }
]
// --- End New Data ---


// --- Utility: shuffle answers for randomized options ---
function shuffle<T>(arr: T[]): T[] {
  const a = arr.slice()
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

// --- Random distractors generator (simple, safe) ---
// ИСПРАВЛЕНИЕ: Добавлены явные типы для TypeScript
function genDistractors(correct: string, topicId: string): string[] {
  // Distractors for CORE_TOPICS (definitions)
  const corePool: Record<string, string[]> = {
    session_attack: [
      'Cross-Site Scripting (XSS) variant',
      'SQL injection by manipulating cookies',
      'Server-Side Request Forgery (SSRF) technique',
      'Broken Access Control via CORS misconfig'
    ],
    hashing: [
      'Two-way reversible transformation',
      'Symmetric key encryption method',
      'Session token generation algorithm',
      'Public key distribution protocol'
    ],
    encryption: [
      'One-way hash function',
      'Compression algorithm',
      'Checksum for data integrity',
      'Session fixation technique'
    ],
    digital_signature: [
      'Password-based authentication',
      'Symmetric encryption of message',
      'TLS handshake protocol',
      'HMAC without keys'
    ]
  }

  // Distractors for QUIZ_APPLICATIONS (applications) - using a general pool for simplicity
  const appPool = [
    'Verifies downloaded files',
    'Secures private keys and wallets',
    'Protects confidential data',
    'Authenticates reports and prescriptions',
    'Used for data integrity checks',
    'Ensures documents are authentic',
    'Secures payment information'
  ]

  let set: string[]
  if (topicId in corePool) {
    set = corePool[topicId]
  } else {
    // If it's an application question, pull distractors from the general app pool
    set = appPool.filter(d => d !== correct)
  }

  // Filter out the correct answer just in case
  set = set.filter(d => d !== correct)
  
  const chosen = shuffle(set).slice(0, 3)
  return shuffle([correct, ...chosen])
}

// Тип для элементов CORE_TOPICS, чтобы использовать его в функциях
type CoreTopic = typeof CORE_TOPICS[number];
type QuizApplication = typeof QUIZ_APPLICATIONS[number];

// --- Functions to generate specific quiz question types ---

// ИСПРАВЛЕНИЕ: Добавлен явный тип для параметра topic
function generateCoreQuizQuestion(topic: CoreTopic) {
  const correct = topic.summary.split('\n')[0]
  const options = genDistractors(correct, topic.id)
  return { id: topic.id, topic: topic.title, prompt: `What best describes ${topic.title}?`, options, answer: correct, source: 'core' }
}

function generateAppQuizQuestion(applicationQuestion: QuizApplication) {
  // Use topic name to pull generic distractors (e.g., 'Hashing' for all hashing app questions)
  const topicId = applicationQuestion.topic.toLowerCase().replace(/\s/g, '_')
  const options = genDistractors(applicationQuestion.answer, topicId)
  return { id: topicId, topic: `${applicationQuestion.topic} in ${applicationQuestion.area}`, prompt: applicationQuestion.question, options, answer: applicationQuestion.answer, source: 'app' }
}


// --- Flashcard component ---
function Flashcard({ front, back }: { front: string, back: string }) {
  const [flipped, setFlipped] = useState(false)
  return (
    <div
      className="w-full max-w-xl mx-auto p-4 rounded-xl shadow-md bg-white dark:bg-slate-800 text-black dark:text-white transition duration-300 ease-in-out hover:shadow-lg"
      onClick={() => setFlipped(s => !s)}
      role="button"
      tabIndex={0}
    >
      <div className="text-sm text-gray-500 dark:text-gray-400 mb-2">Flashcard (tap to flip)</div>
      <div className="text-lg font-semibold">{flipped ? back : front}</div>
    </div>
  )
}

// --- Main app component ---
export default function WebSecApp() {
  const [stage, setStage] = useState('landing')
  const [selectedTopic, setSelectedTopic] = useState('session_attack')
  const [quizQuestion, setQuizQuestion] = useState<any>(null) // Используем any для упрощения типа вопроса

  // Инициализация заметок из localStorage
  const [notes, setNotes] = useState(() => {
    try {
      // ИСПРАВЛЕНО: Корректная загрузка из localStorage при инициализации
      if (typeof window !== 'undefined') {
        return localStorage.getItem('websec_notes') || ''
      }
      return '';
    } catch (e) {
      console.error('Failed to load notes from localStorage', e)
      return ''
    }
  })
  
  // Тип для прогресса
  type ProgressType = Record<string, number>;

  const [progress, setProgress] = useState<ProgressType>(() => {
    try {
      if (typeof window !== 'undefined') {
        return JSON.parse(localStorage.getItem('websec_progress') || '{}')
      }
      return {};
    } catch (e) {
      console.error('Failed to load progress from localStorage', e)
      return {}
    }
  })

  useEffect(() => {
    // Сохранение в localStorage только на клиенте
    if (typeof window !== 'undefined') {
      localStorage.setItem('websec_progress', JSON.stringify(progress))
    }
  }, [progress])
  
  // Сохранение заметок при изменении
  useEffect(() => {
    if (typeof window !== 'undefined') {
        localStorage.setItem('websec_notes', notes);
    }
  }, [notes]);
  

  // Функция для генерации нового вопроса - теперь выбирает из CORE или APPLICATIONS
  const generateNewQuizQuestion = useCallback((topicId: string) => {
    const topic = CORE_TOPICS.find(t => t.id === topicId)
    if (!topic) return null

    // Найти все вопросы из QUIZ_APPLICATIONS, соответствующие выбранной теме
    const appQuestions = QUIZ_APPLICATIONS.filter(q => q.topic.toLowerCase().replace(/\s/g, '_') === topicId)

    // Если есть вопросы по применению для этой темы И случайное число < 0.5, задать вопрос по применению
    // Иначе задать основной вопрос
    if (appQuestions.length > 0 && Math.random() < 0.5) {
      const q = appQuestions[Math.floor(Math.random() * appQuestions.length)]
      return generateAppQuizQuestion(q)
    } else {
      return generateCoreQuizQuestion(topic)
    }
  }, [])
  
  // Генерация рандомизированного вопроса викторины для выбранной темы
  useEffect(() => {
    setQuizQuestion(generateNewQuizQuestion(selectedTopic))
  }, [selectedTopic, generateNewQuizQuestion])

  const reportsBySlug = useMemo(() => {
    const map: Record<string, typeof RESEARCH_REPORTS[number]> = {}
    RESEARCH_REPORTS.forEach(r => (map[r.slug] = r))
    return map
  }, [])

  // mobile-first responsive container
  // Корректный dark:text-white в корневом div
  return (
    // ПРОВЕРЕНО: Корректный dark:text-white в корневом div
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 text-black dark:text-white p-4 sm:p-8">
      <div className="max-w-4xl mx-auto">
        {/* header */}
        <header className="flex items-center justify-between mb-6">
          <div>
            {/* ПРОВЕРЕНО: Заголовки наследуют dark:text-white */}
            <h1 className="text-2xl sm:text-3xl font-extrabold text-black dark:text-white">WebSec L6 — Questioner & Study App</h1>
            <p className="text-sm text-gray-700 dark:text-gray-300">Interactive site to learn session attacks, crypto, and practical defenses.</p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => { setStage('landing'); window.scrollTo({ top: 0, behavior: 'smooth' }) }} className="px-3 py-2 rounded bg-indigo-600 dark:bg-indigo-700 text-white text-sm hover:bg-indigo-700">Home</button>
            <button onClick={() => setStage('reports')} className="px-3 py-2 rounded border border-gray-300 dark:border-gray-600 text-black dark:text-white text-sm hover:bg-slate-200 dark:hover:bg-slate-700">Reports</button>
            <button onClick={() => setStage('study')} className="px-3 py-2 rounded border border-gray-300 dark:border-gray-600 text-black dark:text-white text-sm hover:bg-slate-200 dark:hover:bg-slate-700">Study</button>
          </div>
        </header>

        {/* Landing / Start */}
        {stage === 'landing' && (
          <main className="space-y-6">
            <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm text-black dark:text-white">
              <h2 className="text-xl font-semibold">WebSec L6</h2>
              <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">Ready to start?</p>
              <div className="mt-4 flex flex-col sm:flex-row gap-3">
                <button className="px-4 py-2 rounded bg-indigo-600 text-white hover:bg-indigo-700" onClick={() => setStage('quiz')}>Start Session Attack Section</button>
                <button className="px-4 py-2 rounded border border-gray-300 dark:border-gray-600 text-black dark:text-white hover:bg-slate-100 dark:hover:bg-slate-700" onClick={() => setStage('reports')}>Open Research Reports</button>
                <button className="px-4 py-2 rounded border border-gray-300 dark:border-gray-600 text-black dark:text-white hover:bg-slate-100 dark:hover:bg-slate-700" onClick={() => setStage('study')}>Go to Study / Flashcards</button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {CORE_TOPICS.map(t => (
                <article key={t.id} className="bg-white dark:bg-slate-800 p-3 rounded shadow-sm text-black dark:text-white">
                  <h3 className="font-semibold">{t.title}</h3>
                  <p className="text-sm text-gray-700 dark:text-gray-300 mt-2">{t.summary}</p>
                  <div className="mt-3 flex gap-2">
                    <button className="text-sm px-3 py-1 rounded border border-gray-300 dark:border-gray-600 hover:bg-slate-100 dark:hover:bg-slate-700" onClick={() => { setSelectedTopic(t.id); setStage('quiz') }}>Practice</button>
                    <button className="text-sm px-3 py-1 rounded border border-gray-300 dark:border-gray-600 hover:bg-slate-100 dark:hover:bg-slate-700" onClick={() => { setSelectedTopic(t.id); setStage('study') }}>Study</button>
                  </div>
                </article>
              ))}
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm text-black dark:text-white">
              <h3 className="font-semibold">How this helps you study</h3>
              <ul className="list-disc ml-5 text-sm text-gray-700 dark:text-gray-300 mt-2">
                <li>Short explanations + randomized quiz options help active recall.</li>
                <li>Reports give focused one-page summaries for deeper reading.</li>
                <li>Flashcards and notes let you record ideas and practice spaced repetition manually.</li>
                <li>**New!** Quiz now includes questions about applications in different industries.</li>
              </ul>
            </div>
          </main>
        )}

        {/* Quiz Section */}
        {stage === 'quiz' && quizQuestion && (
          <section className="space-y-4">
            <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm text-black dark:text-white">
              <h2 className="font-bold text-lg">{quizQuestion.topic} — Quick Quiz ({quizQuestion.source === 'app' ? 'Application' : 'Core'})</h2>
              {quizQuestion.source === 'core' && (
                <p className="text-sm text-gray-700 dark:text-gray-300 mt-2">{CORE_TOPICS.find(t => t.id === selectedTopic)?.summary}</p>
              )}

              <div className="mt-4">
                <div className="text-sm font-medium">{quizQuestion.prompt}</div>
                <div className="mt-2 grid grid-cols-1 gap-2">
                  {quizQuestion.options.map((opt: string, idx: number) => (
                    <button
                      key={idx}
                      onClick={() => {
                        const correct = quizQuestion.answer
                        const isCorrect = opt === correct
                        
                        // Обновление прогресса
                        setProgress(p => ({ ...p, [selectedTopic]: (p[selectedTopic] || 0) + (isCorrect ? 1 : 0) }))
                        alert(isCorrect ? 'Correct — well done!' : `Not quite. Correct answer:\n${correct}`)
                        
                        // Генерация нового рандомизированного вопроса
                        setQuizQuestion(generateNewQuizQuestion(selectedTopic))
                      }}
                      // ПРОВЕРЕНО: Корректные стили темной темы для кнопок
                      className="text-left p-3 rounded border border-gray-300 dark:border-gray-600 hover:shadow-md bg-slate-100 dark:bg-slate-700 text-black dark:text-white"
                    >
                      {opt}
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-4 flex gap-2">
                <button className="px-3 py-2 rounded border border-gray-300 dark:border-gray-600 text-black dark:text-white hover:bg-slate-100 dark:hover:bg-slate-700" onClick={() => setStage('landing')}>Back</button>
                <button className="px-3 py-2 rounded bg-indigo-600 text-white hover:bg-indigo-700" onClick={() => {
                   const currentIndex = CORE_TOPICS.findIndex(t => t.id === selectedTopic);
                   // ИСПРАВЛЕНО: Упрощенная логика циклического перехода
                   const nextTopicIndex = (currentIndex + 1) % CORE_TOPICS.length; 
                   setSelectedTopic(CORE_TOPICS[nextTopicIndex].id); 
                }}>Next: {CORE_TOPICS[(CORE_TOPICS.findIndex(t => t.id === selectedTopic) + 1) % CORE_TOPICS.length].title}</button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="bg-white dark:bg-slate-800 p-4 rounded shadow-sm text-black dark:text-white">
                <h4 className="font-semibold">Notes</h4>
                <textarea 
                  className="w-full mt-2 p-2 border rounded resize-y text-black bg-slate-50 dark:bg-slate-900 dark:border-gray-600 dark:text-white" 
                  value={notes} 
                  onChange={e => setNotes(e.target.value)} 
                  placeholder="Write quick notes..." 
                />
                <div className="mt-2 flex gap-2">
                  <button className="px-3 py-2 rounded bg-indigo-600 text-white hover:bg-indigo-700" onClick={() => { 
                    // Сохранение происходит по useEffect, просто уведомление
                    alert('Notes saved locally.') 
                  }}>Save Locally</button>
                  <button className="px-3 py-2 rounded border border-gray-300 dark:border-gray-600 text-black dark:text-white hover:bg-slate-100 dark:hover:bg-slate-700" onClick={() => { setNotes(''); localStorage.removeItem('websec_notes') }}>Clear</button>
                </div>
              </div>

              <div className="bg-white dark:bg-slate-800 p-4 rounded shadow-sm text-black dark:text-white">
                <h4 className="font-semibold">Progress</h4>
                <p className="text-sm text-gray-700 dark:text-gray-300">Stored answers correct count by topic:</p>
                {/* ПРОВЕРЕНО: Корректный класс фона в темной теме */}
                <pre className="mt-2 text-sm bg-slate-100 dark:bg-slate-900 p-2 rounded overflow-x-auto text-black dark:text-white">{JSON.stringify(progress, null, 2)}</pre>
                <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">Progress persists in localStorage for this browser.</div>
              </div>
            </div>
          </section>
        )}

        {/* Study / Flashcards / Reports list */}
        {stage === 'study' && (
          <section className="space-y-4">
            <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm text-black dark:text-white">
              <h2 className="font-bold">Study Section</h2>
              <p className="text-sm text-gray-700 dark:text-gray-300">Flashcards, topic summaries, and quick practice.</p>
              <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3">
                {CORE_TOPICS.map(t => (
                  <div key={t.id} className="p-3 bg-slate-100 dark:bg-slate-900 rounded">
                    <h3 className="font-semibold">{t.title}</h3>
                    <p className="text-sm mt-1 text-gray-700 dark:text-gray-300">{t.summary}</p>
                    <div className="mt-2 flex gap-2">
                      <button className="px-2 py-1 rounded border text-sm border-gray-300 dark:border-gray-600 hover:bg-slate-200 dark:hover:bg-slate-700" onClick={() => { setSelectedTopic(t.id); setStage('quiz') }}>Practice</button>
                      <button className="px-2 py-1 rounded border text-sm border-gray-300 dark:border-gray-600 hover:bg-slate-200 dark:hover:bg-slate-700" onClick={() => { setSelectedTopic(t.id); window.scrollTo({ top: 0, behavior: 'smooth' }) }}>Open</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm text-black dark:text-white">
              <h3 className="font-semibold">Flashcards</h3>
              <div className="mt-3 grid grid-cols-1 gap-3">
                <Flashcard front="What is session hijacking?" back="Stealing or reusing a session identifier (cookie/token) to impersonate a user." />
                <Flashcard front="Why salt passwords?" back="To make each stored hash unique and defeat precomputed tables (rainbow tables)." />
                <Flashcard front="What is a collision-resistant hash?" back="A hash for which finding two inputs with the same output is computationally infeasible." />
                
                {/* НОВЫЕ ФЛЕШ-КАРТЫ ИЗ QUIZ_APPLICATIONS ДЛЯ ПРИМЕРА */}
                {QUIZ_APPLICATIONS.slice(0, 3).map((q, index) => (
                    <Flashcard 
                        key={`app-card-${index}`} 
                        front={`${q.topic} in ${q.area}: ${q.question}`} 
                        back={q.answer} 
                    />
                ))}
              </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm text-black dark:text-white">
              <h3 className="font-semibold">Training — suggested learning path</h3>
              <ol className="list-decimal ml-5 text-sm mt-2 text-gray-700 dark:text-gray-300">
                <li>Basics: HTTP, cookies, SameSite, secure flags, and session management.</li>
                <li>Crypto fundamentals: hashing vs encryption vs signatures + practical libs (bcrypt, libsodium).</li>
                <li>OWASP Top 10 study and practical labs (XSS, SQLi, IDOR, auth flaws).</li>
                <li>Secure coding: parameterized queries, input validation, output encoding.</li>
                <li>Defensive engineering: CSP, rate limiting, WAF, monitoring, secrets management.</li>
              </ol>
            </div>
          </section>
        )}

        {/* Reports list and detail viewer */}
        {stage === 'reports' && (
          <section className="space-y-4">
            <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm text-black dark:text-white">
              <h2 className="font-bold">Research Reports</h2>
              <p className="text-sm text-gray-700 dark:text-gray-300">One-page reports (concise) for each attack.</p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {RESEARCH_REPORTS.map(r => (
                <article key={r.slug} className="bg-white dark:bg-slate-800 p-4 rounded shadow-sm text-black dark:text-white">
                  <h3 className="font-semibold">{r.title}</h3>
                  <p className="text-sm text-gray-700 dark:text-gray-300 mt-2"><strong>What:</strong> {r.what}</p>
                  <p className="text-sm text-gray-700 dark:text-gray-300 mt-2"><strong>How:</strong> {r.how}</p>
                  <p className="text-sm text-gray-700 dark:text-gray-300 mt-2"><strong>Defend:</strong> {r.defend}</p>
                </article>
              ))}
            </div>
          </section>
        )}

      </div>
    </div>
  )
}