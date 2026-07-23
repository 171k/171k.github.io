import * as THREE from 'three';
import { FBXLoader } from 'three/addons/loaders/FBXLoader.js';

const stage = document.getElementById('pond-stage');
const canvas = document.getElementById('pond-canvas');
const loading = document.getElementById('pond-loading');
const loadingDetail = document.getElementById('pond-loading-detail');
const labelLayer = document.getElementById('pond-label-layer');
const interaction = document.getElementById('pond-interaction');
const nearbyTitle = document.getElementById('pond-nearby-title');
const mobileRead = document.getElementById('pond-mobile-read');
const reader = document.getElementById('pond-reader');
const readerTitle = document.getElementById('pond-reader-title');
const readerMeta = document.getElementById('pond-reader-meta');
const readerDescription = document.getElementById('pond-reader-description');
const readerContent = document.getElementById('pond-reader-content');
const readerCanonical = document.getElementById('pond-reader-canonical');
const readerClose = document.getElementById('pond-reader-close');
const readerDone = document.getElementById('pond-reader-done');
const helpToggle = document.getElementById('pond-help-toggle');
const helpPanel = document.getElementById('pond-help');

const collectionOrder = ['quacks', 'ctf', 'tools', 'books', 'projects', 'certifications', 'achievements'];
const collectionLabels = {
  quacks: 'Quacks',
  ctf: 'CTF library',
  tools: 'Toolkit',
  books: 'Library',
  projects: 'Projects',
  certifications: 'Certifications',
  achievements: 'Achievements'
};
const zoneSettings = {
  quacks: { center: [0, -10.2], color: 0x9fcf61 },
  ctf: { center: [8.3, -7.0], color: 0x6eb879 },
  tools: { center: [11.0, 0], color: 0x64aa82 },
  books: { center: [8.2, 7.1], color: 0x86bd69 },
  projects: { center: [0, 10.2], color: 0xb0c55d },
  certifications: { center: [-8.3, 7.0], color: 0x75b98c },
  achievements: { center: [-11.0, 0], color: 0xa6c968 }
};
const assetRoot = '/assets/models/pond/';
const textureRoot = '/assets/images/pond/';
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const coarsePointer = window.matchMedia('(hover: none), (pointer: coarse)').matches;
const movement = { up: false, down: false, left: false, right: false };
const leafEntries = [];
const projectedLabels = [];
const clock = new THREE.Clock();
const duckPosition = new THREE.Vector3(0, -0.40, 0);
const desiredCamera = new THREE.Vector3();
const lookTarget = new THREE.Vector3();
const projection = new THREE.Vector3();
const raycaster = new THREE.Raycaster();
const pointerPosition = new THREE.Vector2();
const pondRadius = 14.1;
const duckRipples = [];
const foliageEntries = [];
const wildlifeEntries = [];
let renderer;
let scene;
let camera;
let duckRoot;
let dragonflyNpc = null;
let nearestLeaf = null;
let hoveredLeaf = null;
let nightMode = false;
let previousFocus = null;
let movementEnabled = true;
let animationFrame = 0;

window.__pondExperienceStarted = true;

function setLoading(message) {
  if (loadingDetail) loadingDetail.textContent = message;
}

function displayTitle(post) {
  return post.collection === 'ctf' && post.ctfEvent ? `${post.ctfEvent}: ${post.title}` : post.title;
}

function selectPosts() {
  if (typeof window.getPondPosts === 'function') return window.getPondPosts();
  const source = document.getElementById('pond-post-data');
  if (!source) return [];
  const posts = JSON.parse(source.textContent);
  return collectionOrder.flatMap((collection) => posts
    .filter((post) => post.collection === collection && post.pond === true)
    .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
    .slice(0, 3));
}

function canUseWebGL() {
  try {
    const probe = document.createElement('canvas');
    return Boolean(window.WebGLRenderingContext && (probe.getContext('webgl2') || probe.getContext('webgl')));
  } catch (error) {
    return false;
  }
}

function createRenderer() {
  renderer = new THREE.WebGLRenderer({ canvas, antialias: !coarsePointer, alpha: false, powerPreference: 'high-performance' });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, coarsePointer ? 1.2 : 1.5));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.05;
  renderer.shadowMap.enabled = false;
}

function createWaterTexture() {
  const textureCanvas = document.createElement('canvas');
  textureCanvas.width = 256;
  textureCanvas.height = 256;
  const context = textureCanvas.getContext('2d');
  const gradient = context.createRadialGradient(128, 118, 18, 128, 128, 180);
  gradient.addColorStop(0, '#337d8d');
  gradient.addColorStop(0.58, '#438f98');
  gradient.addColorStop(1, '#65a69d');
  context.fillStyle = gradient;
  context.fillRect(0, 0, 256, 256);
  const texture = new THREE.CanvasTexture(textureCanvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function createScene() {
  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x9dc9c8);
  scene.fog = new THREE.Fog(0x9dc9c8, 22, 42);

  camera = new THREE.PerspectiveCamera(42, 1, 0.1, 80);
  camera.position.set(9.2, 13.5, 11.2);
  camera.lookAt(duckPosition);

  const hemisphere = new THREE.HemisphereLight(0xf4fff2, 0x41634f, 2.35);
  scene.add(hemisphere);
  const sun = new THREE.DirectionalLight(0xfff2cf, 2.2);
  sun.position.set(-8, 16, 7);
  scene.add(sun);
  scene.userData.hemisphere = hemisphere;
  scene.userData.sun = sun;

  const bank = new THREE.Mesh(
    new THREE.CircleGeometry(27, 72),
    new THREE.MeshStandardMaterial({ color: 0x71935c, roughness: 1 })
  );
  bank.rotation.x = -Math.PI / 2;
  bank.position.y = -0.18;
  scene.add(bank);
  scene.userData.bank = bank;

  const water = new THREE.Mesh(
    new THREE.CircleGeometry(15.2, 64),
    new THREE.MeshStandardMaterial({ map: createWaterTexture(), color: 0xffffff, roughness: 0.42, metalness: 0.01 })
  );
  water.rotation.x = -Math.PI / 2;
  water.position.y = 0;
  water.userData.water = true;
  scene.add(water);
  scene.userData.water = water;

  const shallows = new THREE.Mesh(
    new THREE.RingGeometry(12.9, 15.18, 64),
    new THREE.MeshStandardMaterial({ color: 0x559b93, roughness: 0.72 })
  );
  shallows.rotation.x = -Math.PI / 2;
  shallows.position.y = 0.008;
  scene.add(shallows);
  scene.userData.shallows = shallows;

  const innerShore = new THREE.Mesh(
    new THREE.RingGeometry(14.9, 15.55, 64),
    new THREE.MeshStandardMaterial({ color: 0x8aa761, roughness: 1 })
  );
  innerShore.rotation.x = -Math.PI / 2;
  innerShore.position.y = 0.015;
  scene.add(innerShore);
  scene.userData.innerShore = innerShore;

  for (let index = 0; index < 2; index += 1) {
    const ripple = new THREE.Mesh(
      new THREE.RingGeometry(0.46, 0.51, 32),
      new THREE.MeshBasicMaterial({ color: 0xd4eee7, transparent: true, opacity: 0.28, depthWrite: false })
    );
    ripple.rotation.x = -Math.PI / 2;
    ripple.position.y = 0.028;
    ripple.userData.offset = index * 0.5;
    duckRipples.push(ripple);
    scene.add(ripple);
  }

}

function eachMaterial(object, callback) {
  object.traverse((child) => {
    if (!child.isMesh || !child.material) return;
    const materials = Array.isArray(child.material) ? child.material : [child.material];
    materials.forEach((material) => callback(material, child));
  });
}

function rememberThemeMaterial(object, role) {
  eachMaterial(object, (material, child) => {
    child.userData.pondRole = role;
    if (material.color && material.userData.dayColor === undefined) material.userData.dayColor = material.color.getHex();
    if (material.emissive && material.userData.dayEmissive === undefined) material.userData.dayEmissive = material.emissive.getHex();
    if (material.userData.dayEmissiveIntensity === undefined) material.userData.dayEmissiveIntensity = material.emissiveIntensity || 0;
  });
}

function applyPondTheme() {
  nightMode = document.documentElement.dataset.theme === 'dark';
  if (!scene || !renderer) return;
  stage.classList.toggle('is-night', nightMode);
  scene.background.setHex(nightMode ? 0x071a2c : 0x9dc9c8);
  scene.fog.color.setHex(nightMode ? 0x0b2538 : 0x9dc9c8);
  scene.fog.near = nightMode ? 19 : 22;
  scene.fog.far = nightMode ? 38 : 42;
  renderer.toneMappingExposure = nightMode ? 1.18 : 1.05;

  const environment = scene.userData;
  environment.hemisphere.color.setHex(nightMode ? 0x8fdbea : 0xf4fff2);
  environment.hemisphere.groundColor.setHex(nightMode ? 0x142c3d : 0x41634f);
  environment.hemisphere.intensity = nightMode ? 1.82 : 2.35;
  environment.sun.color.setHex(nightMode ? 0xb8d9ff : 0xfff2cf);
  environment.sun.intensity = nightMode ? 2.55 : 2.2;
  environment.bank.material.color.setHex(nightMode ? 0x29473f : 0x71935c);
  environment.water.material.color.setHex(nightMode ? 0x245374 : 0xffffff);
  environment.water.material.roughness = nightMode ? 0.3 : 0.42;
  environment.shallows.material.color.setHex(nightMode ? 0x265b69 : 0x559b93);
  environment.innerShore.material.color.setHex(nightMode ? 0x4c6950 : 0x8aa761);

  duckRipples.forEach((ripple) => ripple.material.color.setHex(nightMode ? 0x83f4e1 : 0xd4eee7));
  scene.traverse((child) => {
    if (!child.isMesh || !child.material) return;
    if (child.userData.pondRole === 'tuft') {
      child.material.color.setHex(nightMode ? 0x33584f : child.userData.dayColor);
      return;
    }
    const materials = Array.isArray(child.material) ? child.material : [child.material];
    materials.forEach((material) => {
      const role = child.userData.pondRole;
      if (!role || role === 'leaf') return;
      if (material.color && material.userData.dayColor !== undefined) {
        material.color.setHex(material.userData.dayColor);
        if (nightMode && role === 'rock') material.color.lerp(new THREE.Color(0x29465c), 0.58);
        if (nightMode && role === 'duck') material.color.lerp(new THREE.Color(0xb9e5ee), 0.12);
        if (nightMode && role === 'blossom') material.color.lerp(new THREE.Color(0x8ad8cc), 0.28);
        if (nightMode && (role === 'grass' || role === 'cattail')) material.color.lerp(new THREE.Color(0x3f7160), 0.38);
        if (nightMode && role === 'frog') material.color.lerp(new THREE.Color(0x73a878), 0.2);
        if (nightMode && role === 'dragonfly') material.color.lerp(new THREE.Color(0x79e7da), 0.22);
      }
      if (material.emissive) {
        material.emissive.setHex(nightMode ? (role === 'blossom' ? 0x52c4bd : 0x4a8498) : material.userData.dayEmissive);
        material.emissiveIntensity = nightMode ? (role === 'blossom' ? 0.28 : 0.08) : material.userData.dayEmissiveIntensity;
      }
    });
  });
}

function normalizeModel(model, targetHeight) {
  const wrapper = new THREE.Group();
  wrapper.add(model);
  const initial = new THREE.Box3().setFromObject(model);
  const size = initial.getSize(new THREE.Vector3());
  const scale = targetHeight / Math.max(size.y, 0.001);
  model.scale.setScalar(scale);
  const fitted = new THREE.Box3().setFromObject(model);
  const center = fitted.getCenter(new THREE.Vector3());
  model.position.x -= center.x;
  model.position.z -= center.z;
  model.position.y -= fitted.min.y;
  return wrapper;
}

function normalizeFlatModel(model, targetDiameter) {
  const wrapper = new THREE.Group();
  wrapper.add(model);
  const initial = new THREE.Box3().setFromObject(model);
  const size = initial.getSize(new THREE.Vector3());
  const footprint = Math.max(size.x, size.z, 0.001);
  model.scale.setScalar(targetDiameter / footprint);
  const fitted = new THREE.Box3().setFromObject(model);
  const center = fitted.getCenter(new THREE.Vector3());
  model.position.x -= center.x;
  model.position.z -= center.z;
  model.position.y -= fitted.min.y;
  return wrapper;
}

function applyMaterial(root, material) {
  root.traverse((child) => {
    if (!child.isMesh) return;
    child.material = material.clone();
    child.castShadow = false;
    child.receiveShadow = false;
  });
}

function cloneModel(source) {
  const clone = source.clone(true);
  clone.traverse((child) => {
    if (!child.isMesh || !child.material) return;
    child.material = Array.isArray(child.material)
      ? child.material.map((material) => material.clone())
      : child.material.clone();
  });
  return clone;
}

async function loadModels() {
  const manager = new THREE.LoadingManager();
  manager.onProgress = (url, loadedCount, totalCount) => {
    setLoading(`Loading pond pieces ${loadedCount} of ${totalCount}`);
  };
  const fbxLoader = new FBXLoader(manager);
  const textureLoader = new THREE.TextureLoader(manager);
  const plantTexture = await textureLoader.loadAsync(`${textureRoot}pond-plants-atlas.webp`);
  plantTexture.colorSpace = THREE.SRGBColorSpace;
  plantTexture.flipY = false;
  const propsTexture = await textureLoader.loadAsync(`${textureRoot}pond-props-base-color.png`);
  propsTexture.colorSpace = THREE.SRGBColorSpace;
  propsTexture.flipY = false;

  const names = [
    'DuckWhite.fbx',
    'Water_Lily_Blossom_1.fbx',
    'Water_Lily_Leaf_1.fbx',
    'Water_Lily_Leaf_2.fbx',
    'Long_Grass_Patch_1.fbx',
    'Short_Grass_Patch_1.fbx',
    'CatTail_1.fbx',
    'Frog_1.fbx',
    'Dragonfly_1.fbx',
    'Rock_1a.fbx',
    'Rock_2a.fbx',
    'Rock_3a.fbx',
    'Rock_4a.fbx'
  ];
  const loaded = await Promise.all(names.map((name) => fbxLoader.loadAsync(`${assetRoot}${name}`)));
  const models = Object.fromEntries(names.map((name, index) => [name, loaded[index]]));

  const rockMaterial = new THREE.MeshStandardMaterial({ color: 0x687873, roughness: 0.96, metalness: 0 });
  const plantMaterial = new THREE.MeshStandardMaterial({ map: plantTexture, roughness: 0.92, metalness: 0, transparent: true, alphaTest: 0.35, side: THREE.DoubleSide });
  const frogMaterial = new THREE.MeshStandardMaterial({ map: propsTexture, color: 0x91a85f, roughness: 0.9, metalness: 0 });
  [models['DuckWhite.fbx']].forEach((model) => {
    model.traverse((child) => {
      if (!child.isMesh || !child.material) return;
      const materials = Array.isArray(child.material) ? child.material : [child.material];
      materials.forEach((material) => {
        material.roughness = 0.9;
        material.metalness = 0;
      });
    });
  });
  ['Rock_1a.fbx', 'Rock_2a.fbx', 'Rock_3a.fbx', 'Rock_4a.fbx'].forEach((name) => applyMaterial(models[name], rockMaterial));
  ['Water_Lily_Blossom_1.fbx', 'Water_Lily_Leaf_1.fbx', 'Water_Lily_Leaf_2.fbx', 'Long_Grass_Patch_1.fbx', 'Short_Grass_Patch_1.fbx', 'CatTail_1.fbx'].forEach((name) => applyMaterial(models[name], plantMaterial));
  applyMaterial(models['Frog_1.fbx'], frogMaterial);
  applyMaterial(models['Dragonfly_1.fbx'], frogMaterial);
  return models;
}

function addDuck(model) {
  duckRoot = new THREE.Group();
  const visual = normalizeModel(cloneModel(model), 1.55);
  duckRoot.add(visual);
  rememberThemeMaterial(visual, 'duck');
  duckRoot.position.copy(duckPosition);
  scene.add(duckRoot);
}

function addScenery(models) {
  const rockNames = ['Rock_1a.fbx', 'Rock_2a.fbx', 'Rock_3a.fbx', 'Rock_4a.fbx'];
  const rockLayout = [
    [0.08, 15.22, 2, 0.76, 0.18, 1.14, 0.9, -0.11],
    [0.17, 15.48, 0, 1.16, 1.04, 1.18, 0.92, -0.18],
    [0.27, 15.12, 3, 0.68, 2.32, 0.96, 1.12, -0.09],
    [0.91, 15.45, 1, 0.72, 0.42, 1.16, 0.9, -0.1],
    [1.02, 15.16, 3, 1.06, 1.88, 1.05, 1.14, -0.16],
    [1.64, 15.33, 0, 0.7, 2.62, 1.2, 0.86, -0.1],
    [1.75, 15.06, 2, 1.22, 0.72, 1.1, 1.02, -0.2],
    [1.86, 15.5, 1, 0.78, 2.04, 0.95, 1.16, -0.11],
    [2.66, 15.42, 3, 0.94, 1.24, 1.2, 0.88, -0.15],
    [2.77, 15.12, 0, 0.64, 2.78, 0.94, 1.08, -0.08],
    [3.35, 15.36, 1, 0.82, 0.56, 1.14, 0.92, -0.12],
    [3.45, 15.06, 3, 1.28, 2.18, 1.08, 1.2, -0.22],
    [3.57, 15.5, 2, 0.7, 1.16, 1.16, 0.88, -0.09],
    [4.24, 15.46, 0, 0.76, 2.92, 1.2, 0.86, -0.1],
    [4.34, 15.13, 2, 1.12, 0.34, 1.04, 1.16, -0.18],
    [4.45, 15.4, 1, 0.68, 1.76, 0.96, 1.08, -0.09],
    [5.13, 15.14, 3, 1.02, 2.46, 1.16, 0.92, -0.16],
    [5.24, 15.48, 0, 0.66, 0.82, 0.94, 1.14, -0.08],
    [5.76, 15.42, 2, 0.72, 1.44, 1.14, 0.9, -0.1],
    [5.86, 15.08, 1, 1.2, 2.74, 1.08, 1.18, -0.2],
    [5.97, 15.38, 3, 0.74, 0.16, 1.2, 0.88, -0.1]
  ];
  rockLayout.forEach(([angle, radius, modelIndex, height, rotation, scaleX, scaleZ, y]) => {
    const rock = normalizeModel(cloneModel(models[rockNames[modelIndex]]), height);
    rock.position.set(Math.cos(angle) * radius, y, Math.sin(angle) * radius);
    rock.rotation.y = rotation;
    rock.scale.x *= scaleX;
    rock.scale.z *= scaleZ;
    scene.add(rock);
    rememberThemeMaterial(rock, 'rock');
  });

  const grassNames = ['Long_Grass_Patch_1.fbx', 'Short_Grass_Patch_1.fbx'];
  for (let index = 0; index < 12; index += 1) {
    const angle = (index / 12) * Math.PI * 2 + 0.32;
    const radius = 17.0 + (index % 3) * 0.72;
    const grass = normalizeModel(cloneModel(models[grassNames[index % grassNames.length]]), 0.72 + (index % 4) * 0.12);
    grass.position.set(Math.cos(angle) * radius, -0.03, Math.sin(angle) * radius);
    grass.rotation.y = -angle + (index % 2 ? 0.35 : -0.2);
    scene.add(grass);
    rememberThemeMaterial(grass, 'grass');
    foliageEntries.push({ object: grass, baseRotation: grass.rotation.z, phase: index * 0.71, strength: 0.018 + (index % 3) * 0.006 });
  }

  [0.82, 2.46, 4.04, 5.63].forEach((angle, index) => {
    const cattail = normalizeModel(cloneModel(models['CatTail_1.fbx']), 1.18 + (index % 2) * 0.18);
    cattail.position.set(Math.cos(angle) * 16.75, -0.02, Math.sin(angle) * 16.75);
    cattail.rotation.y = -angle;
    scene.add(cattail);
    rememberThemeMaterial(cattail, 'cattail');
    foliageEntries.push({ object: cattail, baseRotation: cattail.rotation.z, phase: index * 1.37, strength: 0.025 });
  });

  const blossom = normalizeFlatModel(cloneModel(models['Water_Lily_Blossom_1.fbx']), 0.72);
  blossom.position.set(4.1, 0.06, -3.3);
  scene.add(blossom);
  rememberThemeMaterial(blossom, 'blossom');

  [
    ['Water_Lily_Leaf_1.fbx', 3.55, -3.0, 1.0, -0.32],
    ['Water_Lily_Leaf_2.fbx', 4.78, -3.55, 0.92, 0.58],
    ['Water_Lily_Leaf_1.fbx', 3.92, -4.18, 0.78, 1.08]
  ].forEach(([name, x, z, size, rotation]) => {
    const leaf = normalizeFlatModel(cloneModel(models[name]), size);
    leaf.position.set(x, 0.035, z);
    leaf.rotation.y = rotation;
    scene.add(leaf);
    rememberThemeMaterial(leaf, 'blossom');
  });

  [2.18, 5.28].forEach((angle, index) => {
    const frog = normalizeModel(cloneModel(models['Frog_1.fbx']), 0.48 + index * 0.05);
    const radius = 16.45 + index * 0.35;
    frog.position.set(Math.cos(angle) * radius, 0.015, Math.sin(angle) * radius);
    frog.rotation.y = -angle + (index ? -0.45 : 0.38);
    scene.add(frog);
    rememberThemeMaterial(frog, 'frog');
    wildlifeEntries.push({ object: frog, baseY: frog.position.y, baseRotation: frog.rotation.y, phase: index * 2.4 });
  });

  const dragonflyVisual = normalizeFlatModel(cloneModel(models['Dragonfly_1.fbx']), 0.82);
  const dragonflyRoot = new THREE.Group();
  dragonflyRoot.add(dragonflyVisual);
  dragonflyRoot.position.set(-3.8, 1.75, 2.6);
  scene.add(dragonflyRoot);
  rememberThemeMaterial(dragonflyVisual, 'dragonfly');
  dragonflyNpc = {
    root: dragonflyRoot,
    visual: dragonflyVisual,
    target: new THREE.Vector3(4.2, 2.35, -3.4),
    velocity: new THREE.Vector3(),
    nextMoveAt: 0,
    speed: 1.15
  };
}

function chooseDragonflyTarget() {
  const angle = Math.random() * Math.PI * 2;
  const radius = 3.2 + Math.random() * 7.6;
  dragonflyNpc.target.set(
    Math.cos(angle) * radius,
    1.35 + Math.random() * 1.8,
    Math.sin(angle) * radius
  );
  dragonflyNpc.speed = 0.85 + Math.random() * 0.75;
  dragonflyNpc.nextMoveAt = 0;
}

function updateDragonfly(elapsed, delta) {
  if (!dragonflyNpc) return;
  const { root, visual, target, velocity } = dragonflyNpc;
  visual.position.y = reducedMotion ? 0 : Math.sin(elapsed * 5.4) * 0.055;
  visual.rotation.z = reducedMotion ? 0 : Math.sin(elapsed * 3.1) * 0.08;
  if (reducedMotion) return;

  const distance = root.position.distanceTo(target);
  if (distance < 0.65) {
    velocity.multiplyScalar(Math.exp(-delta * 4.5));
    if (!dragonflyNpc.nextMoveAt) dragonflyNpc.nextMoveAt = elapsed + 0.35 + Math.random() * 0.9;
    if (elapsed >= dragonflyNpc.nextMoveAt) chooseDragonflyTarget();
  } else {
    dragonflyNpc.nextMoveAt = 0;
    const desiredVelocity = target.clone().sub(root.position).normalize().multiplyScalar(dragonflyNpc.speed);
    velocity.lerp(desiredVelocity, 1 - Math.exp(-delta * 2.2));
  }

  root.position.addScaledVector(velocity, delta);
  if (velocity.lengthSq() > 0.01) {
    const desiredRotation = Math.atan2(velocity.x, velocity.z) + Math.PI;
    root.rotation.y += Math.atan2(
      Math.sin(desiredRotation - root.rotation.y),
      Math.cos(desiredRotation - root.rotation.y)
    ) * (1 - Math.exp(-delta * 5));
  }
}

function updateScenery(elapsed, delta) {
  if (!reducedMotion) {
    foliageEntries.forEach((entry) => {
      entry.object.rotation.z = entry.baseRotation + Math.sin(elapsed * 0.72 + entry.phase) * entry.strength;
    });
  }
  wildlifeEntries.forEach((entry, index) => {
    const breath = reducedMotion ? 1 : 1 + Math.sin(elapsed * 1.7 + entry.phase) * 0.018;
    const hopCycle = reducedMotion ? 0 : Math.sin(elapsed * 0.48 + entry.phase);
    const hop = hopCycle > 0.93 ? (hopCycle - 0.93) * 1.8 : 0;
    entry.object.scale.y = breath;
    entry.object.position.y = entry.baseY + hop;
    entry.object.rotation.y = entry.baseRotation + (reducedMotion ? 0 : Math.sin(elapsed * 0.23 + entry.phase + index) * 0.16);
  });
  updateDragonfly(elapsed, delta);
}

function makeLabel(text, className) {
  const interactive = className === 'pond-leaf-label' || className === 'pond-zone-label';
  const element = document.createElement(interactive ? 'button' : 'span');
  element.className = className;
  element.textContent = text;
  if (interactive) element.type = 'button';
  labelLayer.append(element);
  return element;
}

function moveToZone(collection) {
  const zone = zoneSettings[collection];
  if (!zone || reader.open) return;
  duckPosition.x = zone.center[0];
  duckPosition.z = zone.center[1];
  stage.focus({ preventScroll: true });
}

function addPostLeaves(posts, models) {
  collectionOrder.forEach((collection) => {
    const zone = zoneSettings[collection];
    const zoneAnchor = new THREE.Object3D();
    zoneAnchor.position.set(zone.center[0], 0.62, zone.center[1]);
    scene.add(zoneAnchor);
    const zoneLabel = makeLabel(collectionLabels[collection], 'pond-zone-label');
    zoneLabel.setAttribute('aria-label', `Swim to ${collectionLabels[collection]}`);
    zoneLabel.title = `Swim to ${collectionLabels[collection]}`;
    zoneLabel.addEventListener('click', () => moveToZone(collection));
    projectedLabels.push({ object: zoneAnchor, element: zoneLabel, kind: 'zone' });

    const leafOffsets = [
      [-1.25, -0.55],
      [1.25, 0.5],
      [0, 1.75]
    ];
    posts.filter((post) => post.collection === collection).forEach((post, index) => {
      const offset = leafOffsets[index];
      const leaf = new THREE.Mesh(
        new THREE.CircleGeometry([0.92, 1.02, 0.86][index], 18, 0.22, Math.PI * 2 - 0.44),
        new THREE.MeshStandardMaterial({ color: zone.color, roughness: 0.88, metalness: 0, side: THREE.DoubleSide })
      );
      leaf.position.set(zone.center[0] + offset[0], 0.055, zone.center[1] + offset[1]);
      leaf.rotation.x = -Math.PI / 2;
      leaf.rotation.z = (index + collectionOrder.indexOf(collection)) * 0.74;
      leaf.userData.baseScale = 1;
      leaf.userData.pondRole = 'leaf';
      leaf.userData.dayColor = zone.color;
      leaf.traverse((child) => {
        if (!child.isMesh || !child.material) return;
        child.material.color = new THREE.Color(zone.color);
        child.material.emissive = new THREE.Color(0x000000);
        child.material.emissiveIntensity = 0;
      });
      scene.add(leaf);

      const leafTitle = displayTitle(post);
      const label = makeLabel(leafTitle, 'pond-leaf-label');
      label.setAttribute('aria-label', `Read ${leafTitle}`);
      label.title = `Read ${leafTitle}`;
      label.addEventListener('click', () => openReader(post, label));
      leafEntries.push({ post, object: leaf, label, baseY: leaf.position.y, nearby: false });
      projectedLabels.push({ object: leaf, element: label, kind: 'leaf' });
    });
  });
}

function resize() {
  if (!renderer || !camera || !stage) return;
  const width = Math.max(stage.clientWidth, 1);
  const height = Math.max(stage.clientHeight, 1);
  renderer.setSize(width, height, false);
  camera.aspect = width / height;
  camera.updateProjectionMatrix();
}

function updateMovement(delta, elapsed) {
  if (!duckRoot || !movementEnabled || reader.open) return;
  const direction = new THREE.Vector3(
    Number(movement.right) - Number(movement.left),
    0,
    Number(movement.down) - Number(movement.up)
  );
  if (direction.lengthSq() > 0) {
    direction.normalize();
    const speed = coarsePointer ? 4.3 : 4.9;
    duckPosition.addScaledVector(direction, speed * delta);
    const distance = Math.hypot(duckPosition.x, duckPosition.z);
    if (distance > pondRadius) {
      duckPosition.x = (duckPosition.x / distance) * pondRadius;
      duckPosition.z = (duckPosition.z / distance) * pondRadius;
    }
    const targetRotation = Math.atan2(direction.x, direction.z);
    let difference = targetRotation - duckRoot.rotation.y;
    difference = Math.atan2(Math.sin(difference), Math.cos(difference));
    duckRoot.rotation.y += difference * Math.min(1, delta * 9);
  }
  duckRoot.position.set(duckPosition.x, duckPosition.y + (reducedMotion ? 0 : Math.sin(elapsed * 3.4) * 0.045), duckPosition.z);
  duckRipples.forEach((ripple) => {
    const cycle = (elapsed * 0.55 + ripple.userData.offset) % 1;
    const scale = 0.8 + cycle * 2.15;
    ripple.position.x = duckPosition.x;
    ripple.position.z = duckPosition.z;
    ripple.scale.setScalar(scale);
    ripple.material.opacity = reducedMotion ? 0.12 : (1 - cycle) * 0.25;
  });
}

function updateInteraction(elapsed) {
  let closest = null;
  let closestDistance = Infinity;
  leafEntries.forEach((entry, index) => {
    const distance = duckPosition.distanceTo(entry.object.position);
    if (distance < closestDistance) {
      closest = entry;
      closestDistance = distance;
    }
    const nearby = distance <= 2.45;
    const hovered = entry === hoveredLeaf;
    const highlighted = nearby || hovered;
    entry.nearby = nearby;
    const desiredScale = highlighted ? entry.object.userData.baseScale * 1.14 : entry.object.userData.baseScale;
    const nextScale = THREE.MathUtils.lerp(entry.object.scale.x, desiredScale, reducedMotion ? 1 : 0.14);
    entry.object.scale.setScalar(nextScale);
    entry.object.position.y = entry.baseY + (reducedMotion ? 0 : Math.sin(elapsed * 1.7 + index) * 0.025);
    entry.object.traverse((child) => {
      if (!child.isMesh || !child.material || !child.material.emissive) return;
      child.material.color.setHex(entry.object.userData.dayColor);
      if (nightMode) child.material.color.lerp(new THREE.Color(0x4c9f87), 0.34);
      child.material.emissive.setHex(highlighted ? (nightMode ? 0x9fffd4 : 0x6f7c2f) : (nightMode ? 0x3c9b82 : 0x000000));
      child.material.emissiveIntensity = highlighted ? (nightMode ? 0.7 : 0.42) : (nightMode ? 0.24 : 0);
    });
    entry.label.classList.toggle('is-nearby', nearby);
    entry.label.classList.toggle('is-hovered', hovered);
    entry.label.classList.toggle('is-in-range', distance <= 6.2);
  });

  nearestLeaf = closestDistance <= 2.45 ? closest : null;
  if (interaction) interaction.hidden = !nearestLeaf;
  if (nearbyTitle) nearbyTitle.textContent = nearestLeaf ? displayTitle(nearestLeaf.post) : '';
  if (mobileRead) {
    mobileRead.disabled = !nearestLeaf;
    mobileRead.textContent = nearestLeaf ? 'Read' : 'Find a leaf';
  }
}

function leafAtPointer(event) {
  if (!camera || !canvas || !leafEntries.length) return null;
  const bounds = canvas.getBoundingClientRect();
  pointerPosition.set(
    ((event.clientX - bounds.left) / bounds.width) * 2 - 1,
    -((event.clientY - bounds.top) / bounds.height) * 2 + 1
  );
  raycaster.setFromCamera(pointerPosition, camera);
  const intersections = raycaster.intersectObjects(leafEntries.map((entry) => entry.object), false);
  return intersections.length ? leafEntries.find((entry) => entry.object === intersections[0].object) || null : null;
}

function updateCamera(delta) {
  desiredCamera.set(duckPosition.x + 9.2, 13.5, duckPosition.z + 11.2);
  lookTarget.set(duckPosition.x, 0, duckPosition.z);
  if (reducedMotion) camera.position.copy(desiredCamera);
  else camera.position.lerp(desiredCamera, 1 - Math.exp(-delta * 3.2));
  camera.lookAt(lookTarget);
}

function updateLabels() {
  const bounds = stage.getBoundingClientRect();
  projectedLabels.forEach((entry) => {
    entry.object.getWorldPosition(projection);
    projection.y += entry.kind === 'zone' ? 0.15 : 0.42;
    projection.project(camera);
    const visible = projection.z > -1 && projection.z < 1;
    entry.element.hidden = !visible;
    if (!visible) return;
    const x = (projection.x * 0.5 + 0.5) * bounds.width;
    const y = (-projection.y * 0.5 + 0.5) * bounds.height;
    entry.element.style.transform = `translate3d(${x}px, ${y}px, 0) translate(-50%, -100%)`;
  });
}

function animate() {
  const delta = Math.min(clock.getDelta(), 0.05);
  const elapsed = clock.elapsedTime;
  updateMovement(delta, elapsed);
  updateScenery(elapsed, delta);
  updateInteraction(elapsed);
  updateCamera(delta);
  updateLabels();
  renderer.render(scene, camera);
  animationFrame = window.requestAnimationFrame(animate);
}

function cleanArticle(main) {
  const clone = main.cloneNode(true);
  clone.removeAttribute('id');
  clone.querySelectorAll('script, style, .pdf-launch').forEach((element) => element.remove());
  if (clone.firstElementChild && clone.firstElementChild.tagName === 'H1') clone.firstElementChild.remove();
  clone.querySelectorAll('[id]').forEach((element) => element.removeAttribute('id'));
  clone.querySelectorAll('img').forEach((image) => {
    image.loading = 'lazy';
    image.decoding = 'async';
  });
  return clone.innerHTML;
}

async function openReader(post, trigger) {
  if (!reader || reader.open) return;
  movementEnabled = false;
  previousFocus = trigger || document.activeElement;
  readerTitle.textContent = displayTitle(post);
  readerDescription.textContent = post.description || 'Open this field note to continue reading.';
  readerMeta.textContent = `${collectionLabels[post.collection] || post.collection}  /  ${new Intl.DateTimeFormat('en', { day: '2-digit', month: 'short', year: 'numeric' }).format(new Date(post.date))}`;
  readerCanonical.href = post.url;
  readerContent.innerHTML = '<p class="pond-reader-loading">Fetching this note from the notebook...</p>';
  reader.showModal();
  readerClose.focus();

  try {
    const response = await fetch(post.url, { credentials: 'same-origin' });
    if (!response.ok) throw new Error(`Request returned ${response.status}`);
    const documentText = await response.text();
    const articleDocument = new DOMParser().parseFromString(documentText, 'text/html');
    const articleMain = articleDocument.querySelector('#main-content');
    if (!articleMain) throw new Error('Article content was not found');
    readerContent.innerHTML = cleanArticle(articleMain);
  } catch (error) {
    readerContent.innerHTML = '';
    const message = document.createElement('p');
    message.className = 'pond-reader-error';
    message.textContent = `${post.description || 'This note is available on its normal page.'} Use the full post button below to continue reading.`;
    readerContent.append(message);
  }
}

function closeReader() {
  if (reader.open) reader.close();
}

function handleReaderClosed() {
  movementEnabled = true;
  if (previousFocus && typeof previousFocus.focus === 'function') previousFocus.focus();
  else stage.focus();
}

function setDirection(direction, active) {
  movement[direction] = active;
  const button = document.querySelector(`[data-direction="${direction}"]`);
  if (button) button.classList.toggle('is-active', active);
}

function bindControls() {
  const keyDirections = {
    KeyW: 'up', ArrowUp: 'up',
    KeyS: 'down', ArrowDown: 'down',
    KeyA: 'left', ArrowLeft: 'left',
    KeyD: 'right', ArrowRight: 'right'
  };

  window.addEventListener('keydown', (event) => {
    if (reader.open) return;
    const direction = keyDirections[event.code];
    if (direction) {
      event.preventDefault();
      setDirection(direction, true);
    }
    if (event.code === 'KeyE' && nearestLeaf) {
      event.preventDefault();
      openReader(nearestLeaf.post, stage);
    }
  });
  window.addEventListener('keyup', (event) => {
    const direction = keyDirections[event.code];
    if (direction) {
      event.preventDefault();
      setDirection(direction, false);
    }
  });
  window.addEventListener('blur', () => Object.keys(movement).forEach((direction) => setDirection(direction, false)));

  document.querySelectorAll('.pond-move').forEach((button) => {
    const direction = button.dataset.direction;
    const press = (event) => {
      event.preventDefault();
      button.setPointerCapture(event.pointerId);
      setDirection(direction, true);
    };
    const release = (event) => {
      event.preventDefault();
      setDirection(direction, false);
    };
    button.addEventListener('pointerdown', press);
    button.addEventListener('pointerup', release);
    button.addEventListener('pointercancel', release);
    button.addEventListener('lostpointercapture', () => setDirection(direction, false));
  });

  mobileRead.addEventListener('click', () => {
    if (nearestLeaf) openReader(nearestLeaf.post, mobileRead);
  });
  readerClose.addEventListener('click', closeReader);
  readerDone.addEventListener('click', closeReader);
  reader.addEventListener('close', handleReaderClosed);
  reader.addEventListener('cancel', (event) => {
    event.preventDefault();
    closeReader();
  });
  reader.addEventListener('click', (event) => {
    if (event.target === reader) closeReader();
  });
  helpToggle.addEventListener('click', () => {
    const willOpen = helpPanel.hidden;
    helpPanel.hidden = !willOpen;
    helpToggle.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
  });
  stage.addEventListener('pointerdown', (event) => {
    if (event.target === canvas) stage.focus({ preventScroll: true });
  });
  canvas.addEventListener('pointermove', (event) => {
    hoveredLeaf = leafAtPointer(event);
    canvas.style.cursor = hoveredLeaf ? 'pointer' : '';
  }, { passive: true });
  canvas.addEventListener('pointerleave', () => {
    hoveredLeaf = null;
    canvas.style.cursor = '';
  });
  canvas.addEventListener('pointerup', (event) => {
    const selectedLeaf = leafAtPointer(event);
    if (selectedLeaf) openReader(selectedLeaf.post, stage);
  });
  window.addEventListener('resize', resize, { passive: true });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) Object.keys(movement).forEach((direction) => setDirection(direction, false));
  });
}

async function start() {
  if (!stage || !canvas || !canUseWebGL()) {
    window.showPondFallback();
    return;
  }
  const fallback = document.getElementById('pond-fallback');
  if (fallback) fallback.hidden = true;
  canvas.hidden = false;
  const posts = selectPosts();
  if (!posts.length) {
    window.showPondFallback();
    return;
  }

  try {
    setLoading('Creating the water...');
    createRenderer();
    createScene();
    bindControls();
    resize();
    setLoading('Inviting the duck...');
    const models = await loadModels();
    addDuck(models['DuckWhite.fbx']);
    addScenery(models);
    addPostLeaves(posts, models);
    applyPondTheme();
    loading.hidden = true;
    stage.focus({ preventScroll: true });
    clock.start();
    animate();
  } catch (error) {
    if (animationFrame) window.cancelAnimationFrame(animationFrame);
    console.error('Duck Pond failed to start', error);
    window.showPondFallback();
  }
}

new MutationObserver(applyPondTheme).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
start();
